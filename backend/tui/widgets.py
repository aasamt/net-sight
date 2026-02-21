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
import re
from collections import deque
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Label, Static

from backend.analysis.packet_inspector import render_apdu_detail, render_transport_detail

if TYPE_CHECKING:
    from backend.models.packet import ParsedPacket

# ---------------------------------------------------------------------------
# Packet Filter Expression Parser
# ---------------------------------------------------------------------------

# Map user-facing field names/aliases → row tuple index
# Row: (#=0, Source=1, Destination=2, PDU Type=3, Service=4, Object=5, Size=6)
FILTER_FIELD_ALIASES: dict[str, int] = {
    # Source IP
    "src": 1, "source": 1, "ip.src": 1,
    # Destination IP
    "dst": 2, "dest": 2, "destination": 2, "ip.dst": 2,
    # PDU type
    "pdu": 3, "pdu_type": 3, "type": 3,
    # Service name
    "service": 4, "svc": 4,
    # Object
    "object": 5, "obj": 5,
    # Packet size
    "size": 6, "length": 6, "len": 6,
}

# Regex to tokenize operator-based clauses: field op value
_CLAUSE_RE = re.compile(
    r"^\s*(\w[\w.]*)\s*(==|!=|contains)\s*(.+?)\s*$",
    re.IGNORECASE,
)

# Regex for key:value shorthand
_KV_RE = re.compile(
    r"^\s*(\w[\w.]*):(\S+)\s*$",
    re.IGNORECASE,
)


class _FilterClause:
    """A single filter condition: field op value."""

    __slots__ = ("field_index", "op", "value")

    def __init__(self, field_index: int, op: str, value: str) -> None:
        self.field_index = field_index
        self.op = op  # "==", "!=", "contains"
        self.value = value.lower()

    def matches(self, row: tuple[str, ...]) -> bool:
        """Evaluate this clause against a row tuple."""
        cell = row[self.field_index].lower()
        if self.op == "==":
            return cell == self.value
        if self.op == "!=":
            return cell != self.value
        # "contains"
        return self.value in cell


class _SubstringFilter:
    """Fallback: plain substring match across all columns."""

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text.lower()

    def matches(self, row: tuple[str, ...]) -> bool:
        combined = " ".join(row).lower()
        return self.text in combined


class _AndGroup:
    """A group of clauses joined by AND — all must match."""

    __slots__ = ("clauses",)

    def __init__(self, clauses: list[_FilterClause | _SubstringFilter]) -> None:
        self.clauses = clauses

    def matches(self, row: tuple[str, ...]) -> bool:
        return all(c.matches(row) for c in self.clauses)


class FilterExpression:
    """Parsed filter expression supporting OR-of-AND groups.

    Syntax examples:
        Plain text:        ``ReadProperty``         → global substring
        Key:value:         ``src:192.168.1.1``      → field contains value
        Multiple k:v:      ``src:192.168 service:Read`` → AND
        Operator:          ``src == 192.168.1.1``   → exact match
        Contains:          ``service contains Read`` → substring on field
        AND:               ``src == 1.2.3.4 && service contains Read``
        OR:                ``service == I-Am || service == Who-Is``
        Mixed:             ``src == 1.2.3.4 && pdu == Unconfirmed-REQ || dst == 10.0.0.255``

    Precedence: ``&&`` binds tighter than ``||``.
    Plain text with no recognised operator/field falls back to global substring.
    """

    __slots__ = ("_groups",)

    def __init__(self, groups: list[_AndGroup]) -> None:
        self._groups = groups

    def matches(self, row: tuple[str, ...]) -> bool:
        """True if any OR group matches (i.e. groups are ORed)."""
        return any(g.matches(row) for g in self._groups)

    @classmethod
    def parse(cls, text: str) -> FilterExpression | None:
        """Parse a filter string into a FilterExpression.

        Returns None if the text is empty (meaning "show everything").
        """
        text = text.strip()
        if not text:
            return None

        # Split on || first (lower precedence)
        or_parts = re.split(r"\s*\|\|\s*", text)
        groups: list[_AndGroup] = []

        for or_part in or_parts:
            or_part = or_part.strip()
            if not or_part:
                continue

            # Split on && (higher precedence)
            and_parts = re.split(r"\s*&&\s*", or_part)
            clauses: list[_FilterClause | _SubstringFilter] = []

            for part in and_parts:
                part = part.strip()
                if not part:
                    continue

                clause = cls._parse_clause(part)
                if clause is not None:
                    clauses.append(clause)

            if clauses:
                groups.append(_AndGroup(clauses))

        if not groups:
            return None

        return cls(groups)

    @classmethod
    def _parse_clause(cls, text: str) -> _FilterClause | _SubstringFilter | _MultiClause | None:
        """Parse a single clause — tries operator syntax, then key:value, then substring."""
        # 1. Try operator-based: field == value, field != value, field contains value
        m = _CLAUSE_RE.match(text)
        if m:
            field_name = m.group(1).lower()
            op = m.group(2).lower()
            value = m.group(3)
            idx = FILTER_FIELD_ALIASES.get(field_name)
            if idx is not None:
                return _FilterClause(idx, op, value)
            # Unknown field name → treat entire text as substring
            return _SubstringFilter(text)

        # 2. Try key:value pairs (may have multiple space-separated tokens)
        kv_clauses: list[_FilterClause | _SubstringFilter] = []
        remaining_tokens: list[str] = []
        for token in text.split():
            kv_m = _KV_RE.match(token)
            if kv_m:
                field_name = kv_m.group(1).lower()
                value = kv_m.group(2)
                idx = FILTER_FIELD_ALIASES.get(field_name)
                if idx is not None:
                    kv_clauses.append(_FilterClause(idx, "contains", value))
                    continue
            remaining_tokens.append(token)

        if kv_clauses:
            if remaining_tokens:
                kv_clauses.append(_SubstringFilter(" ".join(remaining_tokens)))
            if len(kv_clauses) == 1:
                return kv_clauses[0]
            return _MultiClause(kv_clauses)

        # 3. Fallback: plain text substring
        return _SubstringFilter(text)


class _MultiClause:
    """Helper for multiple key:value pairs in a single AND segment."""

    __slots__ = ("clauses",)

    def __init__(self, clauses: list[_FilterClause | _SubstringFilter]) -> None:
        self.clauses = clauses

    def matches(self, row: tuple[str, ...]) -> bool:
        return all(c.matches(row) for c in self.clauses)


# ---------------------------------------------------------------------------
# Filter Help Modal Screen
# ---------------------------------------------------------------------------

_FILTER_HELP_TEXT = """\
[b]Packet Filter Reference[/b]

[b]Fields[/b]
  src  (source, ip.src)            Source IP address
  dst  (dest, destination,         Destination IP address
       ip.dst)
  pdu  (pdu_type, type)            PDU type name
  service  (svc)                   BACnet service name
  object  (obj)                    Object type and instance
  size  (length, len)              Packet size in bytes

[b]Operators[/b]
  ==              Exact match         src == 192.168.1.10
  !=              Not equal           dst != 255.255.255.255
  contains        Substring match     service contains Read
  &&              AND                 src == 10.0.0.5 && pdu == Confirmed-REQ
  ||              OR                  service == Who-Is || service == I-Am

[b]Key:Value Shorthand[/b]
  src:192.168.1.10                    Same as: src contains 192.168.1.10
  service:Read                        Same as: service contains Read
  src:10.0 service:Read               Multiple = implicit AND

[b]Plain Text[/b]
  ReadProperty                        Searches all columns (backward compatible)
  192.168                             Partial match anywhere

[b]Examples[/b]
  src == 192.168.1.10                          Packets from specific IP
  service == ReadProperty                      Only ReadProperty requests
  service == Who-Is || service == I-Am         All discovery traffic
  dst:255                                      Broadcast packets
  pdu == Confirmed-REQ                         Confirmed requests only
  src == 10.0.0.5 && service contains Read     ReadProperty from a source
  obj contains Device-200                      Specific device object
  src != 10.0.0.99                             Hide a noisy source
  obj contains AnalogInput                     All analog input objects

  Precedence: && binds tighter than ||
"""


class FilterHelpScreen(ModalScreen):
    """Modal popup showing packet filter syntax help.

    Displayed as an overlay — does not interrupt capture or other background tasks.
    Press Escape or click Close to dismiss.
    """

    DEFAULT_CSS = """
    FilterHelpScreen {
        align: center middle;
    }
    #filter-help-container {
        width: 92;
        max-height: 85%;
        background: $surface;
        border: thick $accent;
        padding: 1 2;
    }
    #filter-help-title {
        dock: top;
        width: 100%;
        height: 1;
        background: $accent;
        color: $text;
        text-style: bold;
        content-align: center middle;
        padding: 0 1;
    }
    #filter-help-body {
        height: 1fr;
        scrollbar-size: 1 1;
    }
    #filter-help-close-row {
        dock: bottom;
        height: 3;
        align: center middle;
    }
    """

    BINDINGS = [("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        from textual.containers import Vertical

        with Vertical(id="filter-help-container"):
            yield Label(" Filter Help", id="filter-help-title")
            with VerticalScroll(id="filter-help-body"):
                yield Static(_FILTER_HELP_TEXT, id="filter-help-content")
            with Horizontal(id="filter-help-close-row"):
                yield Button("Close", variant="primary", id="btn-filter-help-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-filter-help-close":
            self.dismiss()


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
        self._filter_expr: FilterExpression | None = None
        self._filter_text: str = ""
        self._packet_count = 0

    def compose(self) -> ComposeResult:
        yield Label(" Recent Packets", classes="panel-title")
        with Horizontal(id="filter-row"):
            yield Input(
                placeholder="Filter: src == x.x.x.x && service contains Read | plain text",
                id="packet-filter",
            )
            yield Button("?", id="btn-filter-help", classes="filter-help-btn")
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
            self._filter_text = event.value.strip()
            self._filter_expr = FilterExpression.parse(self._filter_text)
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
        """Evaluate the current filter expression against a row.

        Supports Wireshark-style field filters (src == x, service contains y),
        key:value shorthand (src:x), boolean operators (&& / ||), and plain
        text substring fallback.
        """
        if self._filter_expr is None:
            return True
        return self._filter_expr.matches(row)

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
        self._filter_expr = None
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


# ---------------------------------------------------------------------------
# Commands Panel (commands tab)
# ---------------------------------------------------------------------------

class CommandsPanel(Static):
    """Commands panel — send BACnet service requests.

    Currently supports Who-Is broadcast with optional device instance range.
    """

    DEFAULT_CSS = """
    CommandsPanel {
        height: 100%;
    }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._log_entries: list[str] = []

    def compose(self) -> ComposeResult:
        yield Label(" Commands — BACnet Service Requests", classes="panel-title")
        yield Static(
            "  Send BACnet commands to the network. Responses appear in the Traffic tab.",
            id="commands-hint",
        )
        with VerticalScroll(id="commands-scroll"):
            yield Label("  ── Who-Is Broadcast ──", classes="settings-group-header")
            yield Static(
                "  Sends a Who-Is broadcast to discover BACnet devices on the network.\n"
                "  Leave range fields empty for a global Who-Is (all devices respond).\n"
                "  Specify both Low and High to limit discovery to a device ID range.",
                id="whois-desc",
            )
            with Horizontal(classes="settings-row"):
                yield Label("  Low Device ID", classes="settings-label")
                yield Input(
                    value="0",
                    placeholder="0",
                    id="whois-low",
                    classes="settings-input",
                )
                yield Label("Min device instance (0–4194303)", classes="settings-desc")
            with Horizontal(classes="settings-row"):
                yield Label("  High Device ID", classes="settings-label")
                yield Input(
                    value="4194303",
                    placeholder="4194303",
                    id="whois-high",
                    classes="settings-input",
                )
                yield Label("Max device instance (0–4194303)", classes="settings-desc")
        with Horizontal(id="commands-buttons"):
            yield Button("Send Who-Is", variant="primary", id="btn-send-whois")
        yield Static("", id="commands-status")
        with VerticalScroll(id="commands-log-scroll"):
            yield Static("  Command log will appear here.", id="commands-log")

    def set_status(self, message: str, is_error: bool = False) -> None:
        """Update the status line below the buttons."""
        status = self.query_one("#commands-status", Static)
        prefix = "  ✗ " if is_error else "  ✓ "
        status.update(prefix + message)

    def get_whois_range(self) -> tuple[int | None, int | None]:
        """Read the Who-Is range fields.

        Returns:
            (low_limit, high_limit) — both None if fields are empty.

        Raises:
            ValueError: If values are invalid.
        """
        low_text = self.query_one("#whois-low", Input).value.strip()
        high_text = self.query_one("#whois-high", Input).value.strip()

        low: int | None = None
        high: int | None = None

        if low_text:
            low = int(low_text)
        if high_text:
            high = int(high_text)

        return low, high

    def append_log(self, message: str) -> None:
        """Add an entry to the command log."""
        log = self.query_one("#commands-log", Static)
        self._log_entries.append(message)
        log.update("\n".join(f"  {entry}" for entry in self._log_entries))
