"""NetSight TUI widgets — reusable panel components for the dashboard.

Widgets:
    PacketTable        — DataTable showing recent parsed packets (ring buffer)
    PacketDetailPanel  — Decoded packet detail view (raw hex + layer breakdown)
    StatsPanel         — Global traffic statistics
    DevicePanel        — Discovered BACnet devices (compact, right panel)
    DeviceListPanel    — Full device list tab with DataTable (IP, device ID, details)
    TopTalkersPanel    — Top source IPs by packet count
    AnomalyLog         — Recent anomaly alerts
"""

from __future__ import annotations

import datetime
from collections import deque
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Button, DataTable, Input, Label, Static

from backend.analysis.packet_inspector import render_apdu_detail, render_transport_detail

if TYPE_CHECKING:
    from backend.models.packet import ParsedPacket

# ---------------------------------------------------------------------------
# Packet Table (left panel)
# ---------------------------------------------------------------------------

class PacketTable(Static):
    """Recent packets displayed in a DataTable with a ring buffer and filter."""

    DEFAULT_CSS = """
    PacketTable {
        height: 100%;
    }
    """

    def __init__(self, max_rows: int = 50, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.max_rows = max_rows
        self._all_rows: deque[tuple[str, ...]] = deque(maxlen=max_rows)
        self._displayed_keys: list[object] = []
        self._filter_text: str = ""
        self._packet_count = 0

    def compose(self) -> ComposeResult:
        yield Label(" Recent Packets", classes="panel-title")
        yield Input(placeholder="Filter packets...", id="packet-filter")
        table = DataTable(id="packet-table")
        table.cursor_type = "row"
        table.zebra_stripes = True
        yield table

    def on_mount(self) -> None:
        table = self.query_one("#packet-table", DataTable)
        table.add_columns("#", "Source", "Destination", "PDU Type", "Service", "Object", "Size")

    def on_input_changed(self, event: Input.Changed) -> None:
        """Live-filter the table when the user types in the filter field."""
        if event.input.id == "packet-filter":
            self._filter_text = event.value.strip().lower()
            self._rebuild_table()

    def add_packet(
        self,
        packet_id: int,
        source_ip: str,
        dest_ip: str,
        pdu_type: str,
        service: str,
        obj: str,
        length: int,
    ) -> None:
        """Add a packet row, applying the current filter."""
        self._packet_count += 1

        # Truncate long values for display
        service_disp = service[:28] if service else ""
        pdu_disp = pdu_type[:18] if pdu_type else ""
        obj_disp = obj[:24] if obj else ""

        row = (
            str(packet_id),
            source_ip,
            dest_ip,
            pdu_disp,
            service_disp,
            obj_disp,
            str(length),
        )
        self._all_rows.append(row)

        # If it matches the current filter, add it to the visible table
        if self._matches_filter(row):
            table = self.query_one("#packet-table", DataTable)
            key = table.add_row(*row)
            self._displayed_keys.append(key)
            # Evict oldest visible row if too many displayed
            if len(self._displayed_keys) > self.max_rows:
                oldest_key = self._displayed_keys.pop(0)
                try:
                    table.remove_row(oldest_key)
                except Exception:  # noqa: BLE001
                    pass
            table.scroll_end(animate=False)

    def _matches_filter(self, row: tuple[str, ...]) -> bool:
        """Check if any column in the row contains the filter text."""
        if not self._filter_text:
            return True
        combined = " ".join(row).lower()
        return self._filter_text in combined

    def _rebuild_table(self) -> None:
        """Clear and repopulate the table based on the current filter."""
        table = self.query_one("#packet-table", DataTable)
        table.clear()
        self._displayed_keys.clear()

        for row in self._all_rows:
            if self._matches_filter(row):
                key = table.add_row(*row)
                self._displayed_keys.append(key)

        if self._displayed_keys:
            table.scroll_end(animate=False)

    def clear_table(self) -> None:
        """Remove all rows."""
        table = self.query_one("#packet-table", DataTable)
        table.clear()
        self._all_rows.clear()
        self._displayed_keys.clear()
        self._filter_text = ""
        self._packet_count = 0


# ---------------------------------------------------------------------------
# Packet Detail Panel (bottom-left)
# ---------------------------------------------------------------------------

class PacketDetailPanel(Static):
    """Decoded packet detail view — layer breakdown (left) + raw hex dump (right).

    Updated when the user selects a row in the PacketTable DataTable.
    """

    DEFAULT_CSS = """
    PacketDetailPanel {
        height: 100%;
    }
    """

    def compose(self) -> ComposeResult:
        yield Label(" Packet Detail", classes="panel-title")
        with Horizontal(id="detail-split"):
            yield VerticalScroll(
                Label("  Select a packet from the table above", id="detail-content"),
                id="detail-scroll",
            )
            yield VerticalScroll(
                Label("", id="hex-content"),
                id="hex-scroll",
            )

    def show_packet(self, packet: ParsedPacket) -> None:
        """Render full decoded detail for the given packet.

        Delegates to packet_inspector for consistent rendering across
        TUI and other output modes.
        """
        # Left side: APDU / application layer detail
        content = self.query_one("#detail-content", Label)
        content.update(render_apdu_detail(packet))

        # Right side: raw hex + BVLC + NPDU
        hex_content = self.query_one("#hex-content", Label)
        hex_content.update(render_transport_detail(packet))

    def clear_detail(self) -> None:
        """Reset to placeholder text."""
        content = self.query_one("#detail-content", Label)
        content.update("  Select a packet from the table above")
        hex_content = self.query_one("#hex-content", Label)
        hex_content.update("")


# ---------------------------------------------------------------------------
# Stats Panel (right side)
# ---------------------------------------------------------------------------

class StatsPanel(Static):
    """Global traffic statistics panel — updated at 1 Hz."""

    DEFAULT_CSS = """
    StatsPanel {
        height: auto;
        min-height: 8;
    }
    """

    def compose(self) -> ComposeResult:
        yield Label(" Traffic Stats", classes="panel-title")
        yield Label("  Waiting for packets...", id="stats-content")

    def update_stats(
        self,
        total_packets: int,
        total_bytes: int,
        duration: float,
        pps_1s: float,
        bps_1s: float,
        pps_10s: float,
        bps_10s: float,
        confirmed: int,
        unconfirmed: int,
        errors: int,
        rejects: int,
        queue_drops: int,
    ) -> None:
        """Refresh the stats display."""
        lines = [
            f"  Packets: {total_packets:>8}    Bytes: {total_bytes:>10}",
            f"  Duration: {duration:>7.1f}s",
            f"  Rate (1s):  {pps_1s:>7.1f} pps  {bps_1s:>8.0f} Bps",
            f"  Rate (10s): {pps_10s:>7.1f} pps  {bps_10s:>8.0f} Bps",
            f"  Confirmed: {confirmed:>5}  Unconfirmed: {unconfirmed:>5}",
            f"  Errors: {errors:>5}  Rejects: {rejects:>5}",
        ]
        if queue_drops > 0:
            lines.append(f"  ⚠ Queue drops: {queue_drops}")
        content = self.query_one("#stats-content", Label)
        content.update("\n".join(lines))


# ---------------------------------------------------------------------------
# Device Panel (right side)
# ---------------------------------------------------------------------------

class DevicePanel(Static):
    """Discovered BACnet devices panel — updated at 1 Hz."""

    DEFAULT_CSS = """
    DevicePanel {
        height: auto;
        min-height: 6;
    }
    """

    def compose(self) -> ComposeResult:
        yield Label(" Devices", classes="panel-title")
        yield Label("  No devices discovered", id="device-content")

    def update_devices(self, devices: list[object]) -> None:
        """Refresh the device display."""
        if not devices:
            self.query_one("#device-content", Label).update("  No devices discovered")
            return

        lines = [f"  Discovered: {len(devices)}"]
        for dev in devices[:10]:  # Show max 10
            lines.append(
                f"  Device:{dev.instance:<8} {dev.ip:<15} "
                f"({dev.packet_count} pkts)"
            )
        if len(devices) > 10:
            lines.append(f"  ... and {len(devices) - 10} more")

        content = self.query_one("#device-content", Label)
        content.update("\n".join(lines))


# ---------------------------------------------------------------------------
# Top Talkers Panel (right side)
# ---------------------------------------------------------------------------

class TopTalkersPanel(Static):
    """Top talkers ranked by packet count — updated at 1 Hz."""

    DEFAULT_CSS = """
    TopTalkersPanel {
        height: auto;
        min-height: 6;
    }
    """

    def compose(self) -> ComposeResult:
        yield Label(" Top Talkers", classes="panel-title")
        yield Label("  Waiting for data...", id="talkers-content")

    def update_talkers(self, talkers: list[dict]) -> None:
        """Refresh the top talkers display."""
        if not talkers:
            self.query_one("#talkers-content", Label).update("  Waiting for data...")
            return

        lines = []
        for t in talkers[:5]:
            ip = t["ip"]
            pkts = t["packet_count"]
            pct = t["percent"]
            lines.append(f"  {ip:<18} {pkts:>7} pkts ({pct:>5.1f}%)")

        content = self.query_one("#talkers-content", Label)
        content.update("\n".join(lines))


# ---------------------------------------------------------------------------
# Device List Panel (devices tab — full DataTable)
# ---------------------------------------------------------------------------

class DeviceListPanel(Static):
    """Full device list with DataTable showing every unique IP and its BACnet device/object ID.

    Displayed in the "Devices" tab. Updated at 1 Hz from the DeviceRegistry.
    Also includes IPs seen in traffic that have not sent I-Am (shown as unknown device).
    """

    DEFAULT_CSS = """
    DeviceListPanel {
        height: 100%;
    }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._known_ips: set[str] = set()

    def compose(self) -> ComposeResult:
        yield Label(" BACnet Devices", classes="panel-title")
        yield Label(
            "  Discovered devices will appear here as traffic is captured.",
            id="device-list-summary",
        )
        table = DataTable(id="device-list-table")
        table.cursor_type = "row"
        table.zebra_stripes = True
        yield table

    def on_mount(self) -> None:
        table = self.query_one("#device-list-table", DataTable)
        table.add_columns(
            "IP Address",
            "Device ID",
            "Object Type",
            "Vendor ID",
            "Packets",
            "Bytes",
            "First Seen",
            "Last Seen",
        )

    def update_device_list(
        self,
        devices: list[object],
        ip_to_instance: dict[str, int],
        all_seen_ips: list[str] | None = None,
    ) -> None:
        """Rebuild the device table from the current registry state.

        Args:
            devices: List of DeviceEntry objects from DeviceRegistry.
            ip_to_instance: IP→instance mapping for known devices.
            all_seen_ips: Optional list of all IPs seen in traffic
                (from TrafficStats top talkers or per-source tracking).
        """
        table = self.query_one("#device-list-table", DataTable)
        table.clear()

        # Build device-by-IP lookup
        dev_by_ip: dict[str, object] = {}
        for dev in devices:
            dev_by_ip[dev.ip] = dev

        # Collect all IPs: known devices + any extra seen IPs
        all_ips: set[str] = set(dev_by_ip.keys())
        if all_seen_ips:
            all_ips.update(all_seen_ips)

        # Sort: known devices first (by instance), then unknown IPs
        known = sorted(
            [(ip, dev_by_ip[ip]) for ip in all_ips if ip in dev_by_ip],
            key=lambda item: item[1].instance,
        )
        unknown = sorted(ip for ip in all_ips if ip not in dev_by_ip)

        row_count = 0
        for ip, dev in known:
            first = datetime.datetime.fromtimestamp(
                dev.first_seen, tz=datetime.timezone.utc
            ).strftime("%H:%M:%S") if dev.first_seen else "—"
            last = datetime.datetime.fromtimestamp(
                dev.last_seen, tz=datetime.timezone.utc
            ).strftime("%H:%M:%S") if dev.last_seen else "—"

            table.add_row(
                ip,
                str(dev.instance),
                dev.object_type_name,
                str(dev.vendor_id) if dev.vendor_id is not None else "—",
                str(dev.packet_count),
                str(dev.byte_count),
                first,
                last,
            )
            row_count += 1

        for ip in unknown:
            table.add_row(ip, "—", "—", "—", "—", "—", "—", "—")
            row_count += 1

        # Update summary label
        n_known = len(known)
        n_unknown = len(unknown)
        summary_parts = [f"  Total IPs: {row_count}"]
        if n_known:
            summary_parts.append(f"Identified devices: {n_known}")
        if n_unknown:
            summary_parts.append(f"Unknown IPs: {n_unknown}")
        summary = self.query_one("#device-list-summary", Label)
        summary.update("  |  ".join(summary_parts))


# ---------------------------------------------------------------------------
# Anomaly Log (bottom panel)
# ---------------------------------------------------------------------------

class AnomalyLog(Static):
    """Scrolling anomaly alert log — bottom-right panel."""

    DEFAULT_CSS = """
    AnomalyLog {
        height: 100%;
    }
    #anomaly-scroll {
        height: 1fr;
    }
    """

    def __init__(self, max_entries: int = 50, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._entries: deque[str] = deque(maxlen=max_entries)

    def compose(self) -> ComposeResult:
        yield Label(" Anomalies", classes="panel-title")
        with VerticalScroll(id="anomaly-scroll"):
            yield Static("  No anomalies detected", id="anomaly-content")

    def add_anomaly(self, severity: str, message: str) -> None:
        """Add an anomaly entry."""
        icon = "⚠" if severity == "warning" else "🔴" if severity == "critical" else "ℹ"
        self._entries.append(f"  {icon} [{severity.upper():<8}] {message}")
        self._refresh_display()

    def update_count(self, total: int) -> None:
        """Update the title with total count."""
        title = self.query_one(".panel-title", Label)
        title.update(f" Anomalies ({total})")

    def _refresh_display(self) -> None:
        """Redraw the log from deque."""
        content = self.query_one("#anomaly-content", Static)
        if self._entries:
            # Show last entries that fit in the panel
            visible = list(self._entries)[-15:]
            content.update("\n".join(visible))
        else:
            content.update("  No anomalies detected")


# ---------------------------------------------------------------------------
# Settings Panel (settings tab)
# ---------------------------------------------------------------------------

# Field definitions: (key, label, description)
_SETTINGS_FIELDS: list[tuple[str, str, str]] = [
    # General
    ("window_seconds", "Rate Window (s)", "Sliding window for rate calculations"),
    ("cooldown_seconds", "Alert Cooldown (s)", "Min time between duplicate alerts"),
    ("max_anomalies", "Max Anomalies", "Max anomaly records kept in memory"),
    # Chatty device
    ("chatty_pps", "Chatty Device (pps)", "Per-IP threshold for chatty device alerts"),
    # Broadcast storm
    ("broadcast_pps", "Discovery Flood (pps)", "Who-Is/I-Am/Who-Has/I-Have threshold"),
    ("timesync_pps", "TimeSynchronization (pps)", "TimeSynchronization flood threshold"),
    ("unconfirmed_flood_pps", "Unconfirmed Flood (pps)", "COV/WriteGroup flood threshold"),
    ("router_discovery_pps", "Router Discovery (pps)", "Who-Is-Router/I-Am-Router threshold"),
    # Error rates
    ("error_pps", "Error Rate (pps)", "BACnet-Error response rate threshold"),
    ("reject_pps", "Reject Rate (pps)", "BACnet-Reject response rate threshold"),
    ("abort_pps", "Abort Rate (pps)", "BACnet-Abort response rate threshold"),
]

# Group boundaries for visual separation
_SETTINGS_GROUPS: list[tuple[str, int, int]] = [
    ("General", 0, 3),
    ("Chatty Device", 3, 4),
    ("Broadcast Storm Thresholds", 4, 8),
    ("Error / Reject / Abort Rates", 8, 11),
]


class SettingsPanel(Static):
    """Editable settings panel — shows current thresholds with inline editing.

    The panel displays all anomaly detection settings as labeled Input fields.
    Users can modify values, save to settings.toml, or reset to defaults.
    Changes take effect on the running anomaly detector immediately.
    """

    DEFAULT_CSS = """
    SettingsPanel {
        height: 100%;
    }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._inputs: dict[str, Input] = {}

    def compose(self) -> ComposeResult:
        yield Label(" Settings — Anomaly Detection Thresholds", classes="panel-title")
        yield Static(
            "  Edit values below and press Save. Changes apply immediately.",
            id="settings-hint",
        )
        with VerticalScroll(id="settings-scroll"):
            for group_name, start, end in _SETTINGS_GROUPS:
                yield Label(f"  ── {group_name} ──", classes="settings-group-header")
                for key, label, desc in _SETTINGS_FIELDS[start:end]:
                    with Horizontal(classes="settings-row"):
                        yield Label(f"  {label}", classes="settings-label")
                        yield Input(
                            value="",
                            placeholder="—",
                            id=f"setting-{key}",
                            classes="settings-input",
                        )
                        yield Label(desc, classes="settings-desc")
        with Horizontal(id="settings-buttons"):
            yield Button("Save", variant="success", id="btn-save-settings")
            yield Button("Reset to Defaults", variant="warning", id="btn-reset-settings")
        yield Static("", id="settings-status")

    def load_values(self, values: dict[str, float | int]) -> None:
        """Populate the input fields from a settings dict."""
        for key, _, _ in _SETTINGS_FIELDS:
            input_id = f"setting-{key}"
            try:
                inp = self.query_one(f"#{input_id}", Input)
                val = values.get(key)
                if val is not None:
                    inp.value = self._format_display(val)
            except Exception:
                pass

    def get_values(self) -> dict[str, float | int]:
        """Read current Input field values, returning a dict of valid entries.

        Invalid (non-numeric) fields are skipped.
        """
        result: dict[str, float | int] = {}
        for key, label, _ in _SETTINGS_FIELDS:
            input_id = f"setting-{key}"
            try:
                inp = self.query_one(f"#{input_id}", Input)
                text = inp.value.strip()
                if not text:
                    continue
                if key == "max_anomalies":
                    result[key] = int(float(text))
                else:
                    result[key] = float(text)
            except (ValueError, Exception):
                pass
        return result

    def set_status(self, message: str, is_error: bool = False) -> None:
        """Update the status line below the buttons."""
        status = self.query_one("#settings-status", Static)
        prefix = "  ✗ " if is_error else "  ✓ "
        status.update(prefix + message)

    @staticmethod
    def _format_display(val: float | int) -> str:
        """Format a value for display in an Input field."""
        if isinstance(val, int):
            return str(val)
        if val == int(val):
            return str(int(val))
        return str(val)
