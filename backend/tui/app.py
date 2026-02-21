"""NetSight TUI application — Textual-based dashboard for BACnet/IP traffic.

Provides a top-style fixed-panel dashboard with:
- Recent packets DataTable (left, ring buffer)
- Traffic stats, devices, top talkers (right stack)
- Anomaly log (bottom dock)
- Keyboard: Q quit, P pause/resume, S save to JSONL

Usage (called from main.py):
    app = NetSightApp(transport, args)
    app.run()
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, Label, TabbedContent, TabPane

from backend.analysis.anomaly_detector import AnomalyDetector
from backend.analysis.packet_processor import PacketProcessor
from backend.models.packet import ParsedPacket
from backend.settings import Settings, get_defaults, load_settings, reset_to_defaults, save_settings
from backend.transport.base import RawPacket
from backend.transport.whois_sender import send_whois

from .widgets import (
    AnomalyLog,
    CommandsPanel,
    DeviceListPanel,
    DevicePanel,
    PacketDetailPanel,
    PacketTable,
    SettingsPanel,
    StatsPanel,
    TopTalkersPanel,
)

if TYPE_CHECKING:
    from backend.transport.base import TransportCapture

logger = logging.getLogger("netsight.tui")

VERSION = "0.1.0"


class NetSightApp(App):
    """NetSight TUI — BACnet/IP traffic analyzer dashboard."""

    CSS_PATH = "styles.tcss"
    TITLE = "NetSight"
    SUB_TITLE = "BACnet/IP Traffic Analyzer"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("p", "toggle_pause", "Pause/Resume", show=True),
        Binding("s", "save_packets", "Save JSONL", show=True),
    ]

    def __init__(
        self,
        transport: TransportCapture,
        *,
        is_live: bool = True,
        source_name: str = "",
        max_rows: int = 50,
        save_path: str | None = None,
        replay_speed: float = 0.0,
        settings: Settings | None = None,
    ) -> None:
        super().__init__()
        self._transport = transport
        self._is_live = is_live
        self._source_name = source_name
        self._max_rows = max_rows
        self._save_path = save_path
        self._replay_speed = replay_speed

        # Settings (load from file if not provided)
        self._settings = settings if settings is not None else load_settings()

        # Shared packet processor (owns analysis engines)
        self._processor = PacketProcessor(settings=self._settings)
        self._device_registry = self._processor.device_registry
        self._traffic_stats = self._processor.traffic_stats
        self._anomaly_detector = self._processor.anomaly_detector

        # Packet storage for save and detail lookup
        self._parsed_packets: list[ParsedPacket] = []
        self._packets_by_id: dict[int, ParsedPacket] = {}

        # Async queue for thread-safe packet bridging
        self._queue: asyncio.Queue[RawPacket] = asyncio.Queue(maxsize=10_000)
        self._dropped_count = 0
        self._packet_count = 0
        self._paused = False
        self._replay_complete = False

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        mode = "Live" if self._is_live else "Pcap"
        yield Header()
        yield Label(
            f" {mode}: {self._source_name}  |  Packets: 0  |  Press Q to quit",
            id="status-bar",
        )
        with TabbedContent(id="tabs"):
            with TabPane("Traffic", id="tab-traffic"):
                with Horizontal(id="main-container"):
                    yield PacketTable(max_rows=self._max_rows, id="packet-panel")
                    with Vertical(id="right-stack"):
                        yield StatsPanel(id="stats-panel")
                        yield DevicePanel(id="device-panel")
                        yield TopTalkersPanel(id="top-talkers-panel")
                with Horizontal(id="bottom-container"):
                    yield PacketDetailPanel(id="detail-panel")
                    yield AnomalyLog(id="anomaly-panel")
            with TabPane("Devices", id="tab-devices"):
                yield DeviceListPanel(id="device-list-panel")
            if self._is_live:
                with TabPane("Commands", id="tab-commands"):
                    yield CommandsPanel(id="commands-panel-tab")
            with TabPane("Settings", id="tab-settings"):
                yield SettingsPanel(id="settings-panel-tab")
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def on_mount(self) -> None:
        """Start capture and periodic refresh after the app is mounted."""
        # Wire transport → queue (thread-safe)
        loop = asyncio.get_running_loop()

        def enqueue(raw: RawPacket) -> None:
            try:
                self._queue.put_nowait(raw)
            except asyncio.QueueFull:
                self._dropped_count += 1

        if self._is_live:
            self._transport.on_packet(
                lambda raw: loop.call_soon_threadsafe(enqueue, raw)
            )
        else:
            self._transport.on_packet(enqueue)

        # Start transport
        await self._transport.start()

        # Launch background workers
        self._consumer_task = asyncio.create_task(self._consume_packets())
        self._refresh_timer = self.set_interval(1.0, self._refresh_panels)

        if not self._is_live:
            # Watch for replay completion
            self._replay_watcher = asyncio.create_task(self._watch_replay())

        # Load settings into the Settings tab
        settings_panel = self.query_one("#settings-panel-tab", SettingsPanel)
        settings_panel.load_values(self._settings.anomaly_kwargs())

    async def _watch_replay(self) -> None:
        """Wait for pcap replay to finish, then mark complete."""
        while self._transport.is_running:
            await asyncio.sleep(0.1)
        # Give consumer time to drain remaining packets
        await asyncio.sleep(0.5)
        self._replay_complete = True
        self._update_status_bar()

    # ------------------------------------------------------------------
    # Packet consumer
    # ------------------------------------------------------------------

    async def _consume_packets(self) -> None:
        """Drain the queue: parse → analyze → update UI."""
        while True:
            try:
                raw = await asyncio.wait_for(self._queue.get(), timeout=0.5)
            except TimeoutError:
                if self._replay_complete and self._queue.empty():
                    break
                continue

            if self._paused:
                # Still drain queue to prevent backpressure, but skip display
                continue

            # Parse + analyze via shared processor
            result = self._processor.process(raw)
            self._packet_count += 1
            self._parsed_packets.append(result.parsed)
            self._packets_by_id[result.parsed.id] = result.parsed

            # Update packet table
            packet_table = self.query_one("#packet-panel", PacketTable)
            packet_table.add_packet(
                result.parsed.id,
                result.parsed.effective_source_ip,
                result.parsed.destination_ip,
                result.pdu_type,
                result.service,
                result.obj_str,
                result.parsed.length,
            )

            # Update anomaly log
            anomaly_log = self.query_one("#anomaly-panel", AnomalyLog)
            for anomaly in result.anomalies:
                anomaly_log.add_anomaly(anomaly.severity, anomaly.message)

            # Update status bar packet count
            self._update_status_bar()

            # Auto-save if path given
            if self._save_path:
                self._save_packet_jsonl(result.parsed)

    # ------------------------------------------------------------------
    # Packet selection → detail panel
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(
        self, event: DataTable.RowHighlighted
    ) -> None:
        """When user moves cursor on a packet row, show its decoded detail."""
        table = self.query_one("#packet-table", DataTable)
        try:
            row_data = table.get_row(event.row_key)
        except Exception:  # noqa: BLE001
            return

        # First column is the packet ID string
        try:
            packet_id = int(row_data[0])
        except (ValueError, IndexError):
            return

        packet = self._packets_by_id.get(packet_id)
        if packet:
            detail_panel = self.query_one("#detail-panel", PacketDetailPanel)
            detail_panel.show_packet(packet)

    def _save_packet_jsonl(self, parsed: ParsedPacket) -> None:
        """Append a single parsed packet to the JSONL file."""
        try:
            with open(self._save_path, "a", encoding="utf-8") as f:
                f.write(parsed.model_dump_json() + "\n")
        except OSError as e:
            logger.warning("Failed to write packet to %s: %s", self._save_path, e)

    # ------------------------------------------------------------------
    # Periodic refresh (1 Hz)
    # ------------------------------------------------------------------

    def _refresh_panels(self) -> None:
        """Update stats, devices, and top talkers panels."""
        if self._traffic_stats.total_packets == 0:
            return

        # Stats
        summary = self._traffic_stats.get_summary()
        rates = self._traffic_stats.get_rates()

        stats_panel = self.query_one("#stats-panel", StatsPanel)
        stats_panel.update_stats(
            total_packets=summary["total_packets"],
            total_bytes=summary["total_bytes"],
            duration=summary["duration_seconds"],
            pps_1s=rates["1s"]["pps"],
            bps_1s=rates["1s"]["bps"],
            pps_10s=rates["10s"]["pps"],
            bps_10s=rates["10s"]["bps"],
            confirmed=summary["confirmed_count"],
            unconfirmed=summary["unconfirmed_count"],
            errors=summary["error_count"],
            rejects=summary["reject_count"],
            queue_drops=self._dropped_count,
        )

        # Devices (compact panel in right stack)
        devices = self._device_registry.get_all_devices()
        device_panel = self.query_one("#device-panel", DevicePanel)
        device_panel.update_devices(devices)

        # Device list tab (full DataTable)
        ip_to_instance = self._device_registry.get_ip_to_instance()
        all_seen_ips = self._traffic_stats.get_all_source_ips()
        device_list = self.query_one("#device-list-panel", DeviceListPanel)
        device_list.update_device_list(devices, ip_to_instance, all_seen_ips)

        # Top talkers
        talkers = self._traffic_stats.get_top_talkers(5)
        talkers_panel = self.query_one("#top-talkers-panel", TopTalkersPanel)
        talkers_panel.update_talkers(talkers)

        # Anomaly count
        anomaly_log = self.query_one("#anomaly-panel", AnomalyLog)
        anomaly_log.update_count(self._anomaly_detector.get_anomaly_count())

    # ------------------------------------------------------------------
    # Status bar
    # ------------------------------------------------------------------

    def _update_status_bar(self) -> None:
        """Update the status bar text."""
        mode = "Live" if self._is_live else "Pcap"
        status = ""
        if self._paused:
            status = " [PAUSED]"
        elif self._replay_complete:
            status = " [Replay complete]"

        bar = self.query_one("#status-bar", Label)
        bar.update(
            f" {mode}: {self._source_name}  |  "
            f"Packets: {self._packet_count}  |  "
            f"Drops: {self._dropped_count}"
            f"{status}  |  Press Q to quit"
        )

    # ------------------------------------------------------------------
    # Key bindings
    # ------------------------------------------------------------------

    def action_toggle_pause(self) -> None:
        """Toggle pause/resume of packet display."""
        self._paused = not self._paused
        self._update_status_bar()
        self.notify(
            "Paused" if self._paused else "Resumed",
            severity="warning" if self._paused else "information",
        )

    def action_save_packets(self) -> None:
        """Save all captured packets to a JSONL file."""
        if not self._parsed_packets:
            self.notify("No packets to save", severity="warning")
            return

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"netsight_capture_{timestamp}.jsonl"

        try:
            with open(filename, "w", encoding="utf-8") as f:
                for pkt in self._parsed_packets:
                    f.write(pkt.model_dump_json() + "\n")
            self.notify(
                f"Saved {len(self._parsed_packets)} packets to {filename}",
                severity="information",
            )
        except OSError as e:
            self.notify(f"Save failed: {e}", severity="error")

    async def action_quit(self) -> None:
        """Stop capture and exit."""
        try:
            await self._transport.stop()
        except Exception:  # noqa: BLE001
            pass

        # Cancel background tasks
        if hasattr(self, "_consumer_task"):
            self._consumer_task.cancel()
        if hasattr(self, "_replay_watcher"):
            self._replay_watcher.cancel()

        self.exit()

    # ------------------------------------------------------------------
    # Settings tab — Save / Reset handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses in Settings and Commands tabs."""
        if event.button.id == "btn-save-settings":
            self._apply_and_save_settings()
        elif event.button.id == "btn-reset-settings":
            self._reset_settings_to_defaults()
        elif event.button.id == "btn-send-whois":
            self._send_whois()

    def _apply_and_save_settings(self) -> None:
        """Read values from the settings panel, apply to detector, and save to file."""
        panel = self.query_one("#settings-panel-tab", SettingsPanel)
        values = panel.get_values()

        if not values:
            panel.set_status("No valid values to save", is_error=True)
            return

        # Validate: all values must be positive numbers
        for key, val in values.items():
            if val <= 0:
                panel.set_status(f"'{key}' must be positive (got {val})", is_error=True)
                return

        # Update the settings object
        for key, val in values.items():
            setattr(self._settings.anomaly, key, val)

        # Rebuild the anomaly detector with new thresholds
        self._anomaly_detector = AnomalyDetector(**self._settings.anomaly_kwargs())

        # Persist to file
        try:
            path = save_settings(self._settings)
            panel.set_status(f"Saved to {path} — applied to running detector")
            self.notify("Settings saved and applied", severity="information")
        except OSError as e:
            panel.set_status(f"Save failed: {e}", is_error=True)
            self.notify(f"Settings save failed: {e}", severity="error")

    def _reset_settings_to_defaults(self) -> None:
        """Reset all settings to built-in defaults (from settings_default.toml)."""
        try:
            result = reset_to_defaults()
            self._settings.anomaly = result.anomaly
        except OSError as e:
            panel = self.query_one("#settings-panel-tab", SettingsPanel)
            panel.set_status(f"Reset failed: {e}", is_error=True)
            return

        # Rebuild the detector with defaults
        self._anomaly_detector = AnomalyDetector(**self._settings.anomaly_kwargs())

        # Update the UI inputs
        panel = self.query_one("#settings-panel-tab", SettingsPanel)
        panel.load_values(self._settings.anomaly_kwargs())

        panel.set_status(f"Reset to defaults — saved to {self._settings.settings_path}")
        self.notify("Settings reset to defaults", severity="information")

    def _send_whois(self) -> None:
        """Send a Who-Is broadcast from the Commands tab."""
        panel = self.query_one("#commands-panel-tab", CommandsPanel)

        try:
            low, high = panel.get_whois_range()
        except ValueError as e:
            panel.set_status(f"Invalid range: {e}", is_error=True)
            return

        # Determine interface IP from current transport (if live capture)
        interface_ip: str | None = None
        if self._is_live and hasattr(self._transport, "interface"):
            iface = self._transport.interface
            if iface:
                # Try to resolve the interface name to an IP
                try:
                    from scapy.all import conf as scapy_conf

                    iface_obj = scapy_conf.ifaces.get(iface)
                    if iface_obj:
                        interface_ip = getattr(iface_obj, "ip", None)
                except Exception:
                    pass

        result = send_whois(
            interface_ip=interface_ip,
            low_limit=low,
            high_limit=high,
        )

        is_error = result.startswith("Error")
        panel.set_status(result, is_error=is_error)
        panel.append_log(result)

        if not is_error:
            self.notify("Who-Is broadcast sent", severity="information")
        else:
            self.notify(result, severity="error")
