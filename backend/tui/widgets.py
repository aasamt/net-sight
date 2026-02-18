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
from textual.widgets import DataTable, Input, Label, Static

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
        """Render full decoded detail for the given packet."""
        # ── Left side: APDU / application layer detail ──
        lines: list[str] = []

        # Header
        ts = datetime.datetime.fromtimestamp(
            packet.timestamp, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        lines.append(f"  Packet #{packet.id}  |  {ts} UTC  |  {packet.length} bytes")
        lines.append(f"  {packet.effective_source_ip}:{packet.effective_source_port}"
                     f" → {packet.destination_ip}:{packet.destination_port}")
        if packet.parse_error:
            lines.append(f"  ⚠ Parse error: {packet.parse_error}")
        lines.append("")

        # APDU Layer
        lines.append("  ─── APDU Layer ───")
        if packet.apdu:
            a = packet.apdu
            lines.append(f"  PDU Type:      {a.pdu_type} ({a.pdu_type_name})")
            if a.service_choice is not None:
                lines.append(f"  Service:       {a.service_choice} ({a.service_name})")
            lines.append(f"  Confirmed:     {a.is_confirmed}")
            if a.invoke_id is not None:
                lines.append(f"  Invoke ID:     {a.invoke_id}")
            if a.segmented:
                lines.append(f"  Segmented:     Yes (more={a.more_follows},"
                             f" seq={a.sequence_number}, win={a.window_size})")
            if a.max_segments is not None:
                lines.append(f"  Max Segments:  {a.max_segments}")
            if a.max_apdu_length is not None:
                lines.append(f"  Max APDU Len:  {a.max_apdu_length}")
            if a.object_identifier:
                obj = a.object_identifier
                lines.append(f"  Object:        {obj.object_type_name}"
                             f" (type={obj.object_type},"
                             f" instance={obj.instance})")
            if a.property_identifier is not None:
                prop_line = (f"  Property:      {a.property_identifier}"
                             f" ({a.property_name})")
                if a.property_array_index is not None:
                    prop_line += f" [index={a.property_array_index}]"
                lines.append(prop_line)
            if a.iam_fields:
                iam = a.iam_fields
                lines.append("")
                lines.append("  ─── I-Am Detail ───")
                lines.append(f"  Device Instance:   {iam.device_instance}")
                lines.append(f"  Max APDU Length:   {iam.max_apdu_length}")
                lines.append(f"  Segmentation:      {iam.segmentation_supported}"
                             f" ({iam.segmentation_name})")
                lines.append(f"  Vendor ID:         {iam.vendor_id}")
            if a.who_is_range:
                wh = a.who_is_range
                lines.append("")
                lines.append("  ─── Who-Is Range ───")
                lines.append(f"  Low Limit:         {wh.low_limit}")
                lines.append(f"  High Limit:        {wh.high_limit}")
            if a.error_class is not None:
                lines.append(f"  Error Class:   {a.error_class}"
                             f" ({a.error_class_name})")
                lines.append(f"  Error Code:    {a.error_code}")
            if a.reject_reason is not None:
                lines.append(f"  Reject Reason: {a.reject_reason}"
                             f" ({a.reject_reason_name})")
            if a.abort_reason is not None:
                lines.append(f"  Abort Reason:  {a.abort_reason}"
                             f" ({a.abort_reason_name})")
        elif packet.npdu and packet.npdu.is_network_message:
            lines.append("  (network layer message — no APDU)")
        else:
            lines.append("  (not decoded)")

        # Update left side
        content = self.query_one("#detail-content", Label)
        content.update("\n".join(lines))

        # ── Right side: raw hex + BVLC + NPDU ──
        rlines: list[str] = []

        # Raw Hex Dump
        rlines.append("  ─── Raw Bytes ───")
        rlines.extend(self._hex_dump(bytes.fromhex(packet.raw_hex)))
        rlines.append("")

        # BVLC Layer
        rlines.append("  ─── BVLC Layer ───")
        if packet.bvlc:
            b = packet.bvlc
            rlines.append(f"  Type:          0x{b.type:02X} (BACnet/IPv4)")
            rlines.append(f"  Function:      0x{b.function:02X} ({b.function_name})")
            rlines.append(f"  Length:        {b.length} bytes")
            if b.originating_ip:
                rlines.append(f"  Originator:    {b.originating_ip}:{b.originating_port}")
            if b.result_code is not None:
                rlines.append(f"  Result:        0x{b.result_code:04X}"
                              f" ({b.result_name or 'Unknown'})")
            if b.ttl is not None:
                rlines.append(f"  TTL:           {b.ttl}s")
        else:
            rlines.append("  (not decoded)")
        rlines.append("")

        # NPDU Layer
        rlines.append("  ─── NPDU Layer ───")
        if packet.npdu:
            n = packet.npdu
            rlines.append(f"  Version:       0x{n.version:02X}")
            rlines.append(f"  Message Type:  {'Network' if n.is_network_message else 'APDU'}")
            rlines.append(f"  Expecting Reply: {n.expecting_reply}")
            rlines.append(f"  Priority:      {n.priority} ({n.priority_name})")
            if n.destination_network is not None:
                dnet = n.destination_network
                dnet_str = "Broadcast-All" if dnet == 0xFFFF else str(dnet)
                rlines.append(f"  Dest Network:  {dnet_str}")
                if n.destination_address:
                    rlines.append(f"  Dest Address:  {n.destination_address}")
            if n.source_network is not None:
                rlines.append(f"  Src Network:   {n.source_network}")
                if n.source_address:
                    rlines.append(f"  Src Address:   {n.source_address}")
            if n.hop_count is not None:
                rlines.append(f"  Hop Count:     {n.hop_count}")
            if n.is_network_message:
                rlines.append(f"  Net Msg Type:  0x{n.network_message_type:02X}"
                              f" ({n.network_message_name})")
                if n.reject_reason is not None:
                    rlines.append(f"  Reject Reason: {n.reject_reason}"
                                  f" ({n.reject_reason_name})")
                if n.vendor_id is not None:
                    rlines.append(f"  Vendor ID:     {n.vendor_id}")
        else:
            rlines.append("  (not decoded)")

        hex_content = self.query_one("#hex-content", Label)
        hex_content.update("\n".join(rlines))

    @staticmethod
    def _hex_dump(data: bytes, width: int = 16) -> list[str]:
        """Format bytes as a hex dump (offset | hex bytes)."""
        lines: list[str] = []
        for offset in range(0, len(data), width):
            chunk = data[offset:offset + width]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            lines.append(f"  {offset:04X}  {hex_part}")
        return lines

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
            import datetime as _dt

            first = _dt.datetime.fromtimestamp(
                dev.first_seen, tz=_dt.timezone.utc
            ).strftime("%H:%M:%S") if dev.first_seen else "—"
            last = _dt.datetime.fromtimestamp(
                dev.last_seen, tz=_dt.timezone.utc
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
            # Show last entries that fit in the panel
            visible = list(self._entries)[-15:]
            content.update("\n".join(visible))
        else:
            content.update("  No anomalies detected")
