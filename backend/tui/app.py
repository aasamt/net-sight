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
from textual.widgets import Footer, Header, Label

from backend.analysis.anomaly_detector import AnomalyDetector
from backend.analysis.device_registry import DeviceRegistry
from backend.analysis.traffic_stats import TrafficStats
from backend.models.packet import ParsedPacket
from backend.parsers.pipeline import parse_packet
from backend.transport.base import RawPacket

from .widgets import AnomalyLog, DevicePanel, PacketTable, StatsPanel, TopTalkersPanel

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
    ) -> None:
        super().__init__()
        self._transport = transport
        self._is_live = is_live
        self._source_name = source_name
        self._max_rows = max_rows
        self._save_path = save_path
        self._replay_speed = replay_speed

        # Analysis engines
        self._device_registry = DeviceRegistry()
        self._traffic_stats = TrafficStats()
        self._anomaly_detector = AnomalyDetector()

        # Packet storage for save
        self._parsed_packets: list[ParsedPacket] = []

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
        with Horizontal(id="main-container"):
            yield PacketTable(max_rows=self._max_rows, id="packet-panel")
            with Vertical(id="right-stack"):
                yield StatsPanel(id="stats-panel")
                yield DevicePanel(id="device-panel")
                yield TopTalkersPanel(id="top-talkers-panel")
        yield AnomalyLog(id="anomaly-panel")
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

            # Parse
            parsed = parse_packet(raw)
            self._packet_count += 1
            self._parsed_packets.append(parsed)

            # Feed analysis engines
            self._device_registry.process_packet(parsed)
            self._traffic_stats.process_packet(parsed)
            anomalies = self._anomaly_detector.process_packet(parsed)

            # Update packet table
            service = ""
            if parsed.apdu and parsed.apdu.service_name:
                service = parsed.apdu.service_name
            elif parsed.npdu and parsed.npdu.network_message_name:
                service = parsed.npdu.network_message_name
            elif parsed.bvlc:
                service = parsed.bvlc.function_name

            bvlc_fn = parsed.bvlc.function_name if parsed.bvlc else "Unknown"

            packet_table = self.query_one("#packet-panel", PacketTable)
            packet_table.add_packet(
                parsed.id,
                parsed.effective_source_ip,
                parsed.destination_ip,
                bvlc_fn,
                service,
                parsed.length,
            )

            # Update anomaly log
            anomaly_log = self.query_one("#anomaly-panel", AnomalyLog)
            for anomaly in anomalies:
                anomaly_log.add_anomaly(anomaly.severity, anomaly.message)

            # Update status bar packet count
            self._update_status_bar()

            # Auto-save if path given
            if self._save_path:
                self._save_packet_jsonl(parsed)

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

        # Devices
        devices = self._device_registry.get_all_devices()
        device_panel = self.query_one("#device-panel", DevicePanel)
        device_panel.update_devices(devices)

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
