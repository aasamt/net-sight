"""NetSight TUI widgets — reusable panel components for the dashboard.

Widgets:
    PacketTable  — DataTable showing recent parsed packets (ring buffer)
    StatsPanel   — Global traffic statistics
    DevicePanel  — Discovered BACnet devices
    TopTalkersPanel — Top source IPs by packet count
    AnomalyLog   — Recent anomaly alerts
"""

from __future__ import annotations

from collections import deque

from textual.app import ComposeResult
from textual.widgets import DataTable, Label, Static

# ---------------------------------------------------------------------------
# Packet Table (left panel)
# ---------------------------------------------------------------------------

class PacketTable(Static):
    """Recent packets displayed in a DataTable with a ring buffer."""

    DEFAULT_CSS = """
    PacketTable {
        height: 100%;
    }
    """

    def __init__(self, max_rows: int = 50, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.max_rows = max_rows
        self._row_keys: deque[object] = deque(maxlen=max_rows)
        self._packet_count = 0

    def compose(self) -> ComposeResult:
        yield Label(" Recent Packets", classes="panel-title")
        table = DataTable(id="packet-table")
        table.cursor_type = "row"
        table.zebra_stripes = True
        yield table

    def on_mount(self) -> None:
        table = self.query_one("#packet-table", DataTable)
        table.add_columns("#", "Source", "Destination", "BVLC", "Service", "Size")

    def add_packet(
        self,
        packet_id: int,
        source_ip: str,
        dest_ip: str,
        bvlc_function: str,
        service: str,
        length: int,
    ) -> None:
        """Add a packet row, evicting oldest if at capacity."""
        table = self.query_one("#packet-table", DataTable)
        self._packet_count += 1

        # Evict oldest row if at capacity
        if len(self._row_keys) >= self.max_rows:
            oldest_key = self._row_keys[0]
            try:
                table.remove_row(oldest_key)
            except Exception:  # noqa: BLE001
                pass
            self._row_keys.popleft()

        # Truncate long values for display
        service_disp = service[:28] if service else ""
        bvlc_disp = bvlc_function[:18] if bvlc_function else ""

        key = table.add_row(
            str(packet_id),
            source_ip,
            dest_ip,
            bvlc_disp,
            service_disp,
            str(length),
        )
        self._row_keys.append(key)

        # Auto-scroll to bottom
        table.scroll_end(animate=False)

    def clear_table(self) -> None:
        """Remove all rows."""
        table = self.query_one("#packet-table", DataTable)
        table.clear()
        self._row_keys.clear()
        self._packet_count = 0


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
# Anomaly Log (bottom panel)
# ---------------------------------------------------------------------------

class AnomalyLog(Static):
    """Scrolling anomaly alert log — bottom dock panel."""

    DEFAULT_CSS = """
    AnomalyLog {
        height: 8;
    }
    """

    def __init__(self, max_entries: int = 50, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._entries: deque[str] = deque(maxlen=max_entries)

    def compose(self) -> ComposeResult:
        yield Label(" Anomalies", classes="panel-title")
        yield Label("  No anomalies detected", id="anomaly-content")

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
        content = self.query_one("#anomaly-content", Label)
        if self._entries:
            # Show last 5 entries that fit in the panel
            visible = list(self._entries)[-5:]
            content.update("\n".join(visible))
        else:
            content.update("  No anomalies detected")
