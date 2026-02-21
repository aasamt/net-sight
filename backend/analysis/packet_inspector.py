"""Packet inspector — deep packet inspection with configurable detail levels.

Provides human-readable descriptions of BACnet packets at three detail levels:
- summary: one-line overview (service name, object ID, key fields)
- normal: multi-line with all parsed layer fields
- full: everything including raw hex, all NPDU routing fields, segmentation info

Also provides split rendering functions for TUI panels:
- render_apdu_detail: left panel (APDU/application layer detail)
- render_transport_detail: right panel (raw hex + BVLC + NPDU)

This module renders ParsedPacket data for terminal display and is also used
by the REST API for detailed packet views.
"""

from __future__ import annotations

import datetime
import logging
from enum import Enum

from backend.models.packet import ParsedPacket

logger = logging.getLogger(__name__)


class DetailLevel(str, Enum):
    """Inspection detail levels."""

    SUMMARY = "summary"
    NORMAL = "normal"
    FULL = "full"


def inspect_packet(packet: ParsedPacket, level: DetailLevel = DetailLevel.NORMAL) -> str:
    """Generate a human-readable inspection of a parsed packet.

    Args:
        packet: The parsed packet to inspect.
        level: Detail level (summary, normal, full).

    Returns:
        Formatted string with packet details.
    """
    if level == DetailLevel.SUMMARY:
        return _inspect_summary(packet)
    elif level == DetailLevel.NORMAL:
        return _inspect_normal(packet)
    else:
        return _inspect_full(packet)


def _inspect_summary(packet: ParsedPacket) -> str:
    """One-line summary: same as ParsedPacket.summary property."""
    return packet.summary


def _inspect_normal(packet: ParsedPacket) -> str:
    """Multi-line inspection with key fields from each layer."""
    lines: list[str] = []
    lines.append(f"Packet #{packet.id}  ({packet.length} bytes)")
    lines.append(
        f"  {packet.effective_source_ip}:{packet.effective_source_port}"
        f" → {packet.destination_ip}:{packet.destination_port}"
    )

    # BVLC layer
    if packet.bvlc:
        b = packet.bvlc
        line = f"  BVLC: {b.function_name} (0x{b.function:02X}), length={b.length}"
        if b.originating_ip:
            line += f", orig={b.originating_ip}:{b.originating_port}"
        if b.result_code is not None:
            line += f", result={b.result_name}"
        if b.ttl is not None:
            line += f", ttl={b.ttl}s"
        lines.append(line)

    # NPDU layer
    if packet.npdu:
        n = packet.npdu
        line = f"  NPDU: v{n.version}, priority={n.priority_name}"
        if n.is_network_message:
            line += f", NETWORK-MSG: {n.network_message_name}"
            if n.reject_reason is not None:
                line += f" (reason={n.reject_reason_name})"
        else:
            line += ", expecting-reply" if n.expecting_reply else ""
        if n.destination_network is not None:
            if n.destination_network == 0xFFFF:
                line += ", DNET=broadcast"
            else:
                line += f", DNET={n.destination_network}"
                if n.destination_address:
                    line += f", DADR={n.destination_address}"
        if n.source_network is not None:
            line += f", SNET={n.source_network}"
            if n.source_address:
                line += f", SADR={n.source_address}"
        if n.hop_count is not None:
            line += f", hops={n.hop_count}"
        lines.append(line)

    # APDU layer
    if packet.apdu:
        a = packet.apdu
        line = f"  APDU: {a.pdu_type_name}"
        if a.service_name:
            line += f" — {a.service_name}"
        if a.invoke_id is not None:
            line += f", invoke={a.invoke_id}"
        if a.object_identifier:
            oid = a.object_identifier
            line += f", obj={oid.object_type_name}:{oid.instance}"
        if a.error_class_name:
            line += f", error={a.error_class_name}/{a.error_code}"
        if a.reject_reason_name:
            line += f", reject={a.reject_reason_name}"
        if a.abort_reason_name:
            line += f", abort={a.abort_reason_name}"
        lines.append(line)

    # Parse error
    if packet.parse_error:
        lines.append(f"  ⚠ Parse error: {packet.parse_error}")

    return "\n".join(lines)


def _inspect_full(packet: ParsedPacket) -> str:
    """Full inspection with all fields including raw hex."""
    lines: list[str] = []
    lines.append(f"{'═' * 70}")
    lines.append(f"Packet #{packet.id}")
    lines.append(f"{'─' * 70}")

    # IP layer
    lines.append("IP Layer:")
    lines.append(f"  Source:      {packet.source_ip}:{packet.source_port}")
    lines.append(f"  Destination: {packet.destination_ip}:{packet.destination_port}")
    lines.append(f"  Effective:   {packet.effective_source_ip}:{packet.effective_source_port}")
    lines.append(f"  Length:      {packet.length} bytes")
    lines.append(f"  Timestamp:   {packet.timestamp}")

    # BVLC layer
    if packet.bvlc:
        b = packet.bvlc
        lines.append(f"{'─' * 70}")
        lines.append("BVLC Layer:")
        lines.append(f"  Type:     0x{b.type:02X}")
        lines.append(f"  Function: 0x{b.function:02X} ({b.function_name})")
        lines.append(f"  Length:   {b.length}")
        if b.originating_ip:
            lines.append(f"  Originating: {b.originating_ip}:{b.originating_port}")
        if b.result_code is not None:
            lines.append(f"  Result:  0x{b.result_code:04X} ({b.result_name})")
        if b.ttl is not None:
            lines.append(f"  TTL:     {b.ttl}s")

    # NPDU layer
    if packet.npdu:
        n = packet.npdu
        lines.append(f"{'─' * 70}")
        lines.append("NPDU Layer:")
        lines.append(f"  Version:         {n.version}")
        lines.append(f"  Network message: {n.is_network_message}")
        lines.append(f"  Expecting reply: {n.expecting_reply}")
        lines.append(f"  Priority:        {n.priority} ({n.priority_name})")
        if n.destination_network is not None:
            dn = "broadcast" if n.destination_network == 0xFFFF else str(n.destination_network)
            lines.append(f"  DNET:    {dn}")
            lines.append(f"  DADR:    {n.destination_address or '(broadcast)'}")
        if n.source_network is not None:
            lines.append(f"  SNET:    {n.source_network}")
            lines.append(f"  SADR:    {n.source_address}")
        if n.hop_count is not None:
            lines.append(f"  Hop count: {n.hop_count}")
        if n.is_network_message:
            lines.append(f"  Msg type:  0x{n.network_message_type:02X} ({n.network_message_name})")
            if n.vendor_id is not None:
                lines.append(f"  Vendor ID: {n.vendor_id}")
            if n.reject_reason is not None:
                lines.append(f"  Reject:    {n.reject_reason} ({n.reject_reason_name})")

    # APDU layer
    if packet.apdu:
        a = packet.apdu
        lines.append(f"{'─' * 70}")
        lines.append("APDU Layer:")
        lines.append(f"  PDU type:    {a.pdu_type} ({a.pdu_type_name})")
        if a.service_choice is not None:
            lines.append(f"  Service:     {a.service_choice} ({a.service_name})")
        lines.append(f"  Confirmed:   {a.is_confirmed}")
        if a.invoke_id is not None:
            lines.append(f"  Invoke ID:   {a.invoke_id}")
        if a.segmented:
            lines.append(f"  Segmented:   yes (more={a.more_follows})")
            if a.sequence_number is not None:
                lines.append(f"  Seq/Window:  {a.sequence_number}/{a.window_size}")
            if a.max_segments is not None:
                lines.append(f"  Max segs:    {a.max_segments}")
                lines.append(f"  Max APDU:    {a.max_apdu_length}")
        if a.object_identifier:
            oid = a.object_identifier
            lines.append(f"  Object ID:   {oid.object_type_name}:{oid.instance} (type={oid.object_type})")
        if a.error_class_name:
            lines.append(f"  Error class: {a.error_class} ({a.error_class_name})")
            lines.append(f"  Error code:  {a.error_code}")
        if a.reject_reason_name:
            lines.append(f"  Reject:      {a.reject_reason} ({a.reject_reason_name})")
        if a.abort_reason_name:
            lines.append(f"  Abort:       {a.abort_reason} ({a.abort_reason_name})")

    # Raw hex
    lines.append(f"{'─' * 70}")
    lines.append(f"Raw hex: {packet.raw_hex}")

    # Parse error
    if packet.parse_error:
        lines.append(f"⚠ Parse error: {packet.parse_error}")

    lines.append(f"{'═' * 70}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Split rendering for TUI panels
# ---------------------------------------------------------------------------

def render_apdu_detail(packet: ParsedPacket) -> str:
    """Render the APDU/application layer detail (TUI left panel).

    Shows packet header, APDU fields, I-Am/Who-Is detail,
    error/reject/abort info. Matches the former
    PacketDetailPanel.show_packet() left-side output.
    """
    lines: list[str] = []

    # Header
    ts = datetime.datetime.fromtimestamp(
        packet.timestamp, tz=datetime.timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    lines.append(f"  Packet #{packet.id}  |  {ts} UTC  |  {packet.length} bytes")
    lines.append(
        f"  {packet.effective_source_ip}:{packet.effective_source_port}"
        f" → {packet.destination_ip}:{packet.destination_port}"
    )
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
            lines.append(
                f"  Segmented:     Yes (more={a.more_follows},"
                f" seq={a.sequence_number}, win={a.window_size})"
            )
        if a.max_segments is not None:
            lines.append(f"  Max Segments:  {a.max_segments}")
        if a.max_apdu_length is not None:
            lines.append(f"  Max APDU Len:  {a.max_apdu_length}")
        if a.object_identifier:
            obj = a.object_identifier
            lines.append(
                f"  Object:        {obj.object_type_name}"
                f" (type={obj.object_type}, instance={obj.instance})"
            )
        if a.property_identifier is not None:
            prop_line = f"  Property:      {a.property_identifier} ({a.property_name})"
            if a.property_array_index is not None:
                prop_line += f" [index={a.property_array_index}]"
            lines.append(prop_line)
        if a.iam_fields:
            iam = a.iam_fields
            lines.append("")
            lines.append("  ─── I-Am Detail ───")
            lines.append(f"  Device Instance:   {iam.device_instance}")
            lines.append(f"  Max APDU Length:   {iam.max_apdu_length}")
            lines.append(
                f"  Segmentation:      {iam.segmentation_supported}"
                f" ({iam.segmentation_name})"
            )
            lines.append(f"  Vendor ID:         {iam.vendor_id}")
        if a.who_is_range:
            wh = a.who_is_range
            lines.append("")
            lines.append("  ─── Who-Is Range ───")
            lines.append(f"  Low Limit:         {wh.low_limit}")
            lines.append(f"  High Limit:        {wh.high_limit}")
        if a.error_class is not None:
            lines.append(f"  Error Class:   {a.error_class} ({a.error_class_name})")
            lines.append(f"  Error Code:    {a.error_code}")
        if a.reject_reason is not None:
            lines.append(f"  Reject Reason: {a.reject_reason} ({a.reject_reason_name})")
        if a.abort_reason is not None:
            lines.append(f"  Abort Reason:  {a.abort_reason} ({a.abort_reason_name})")
    elif packet.npdu and packet.npdu.is_network_message:
        lines.append("  (network layer message — no APDU)")
    else:
        lines.append("  (not decoded)")

    return "\n".join(lines)


def render_transport_detail(packet: ParsedPacket) -> str:
    """Render the raw hex + BVLC + NPDU layers (TUI right panel).

    Shows raw hex dump, BVLC layer fields, and NPDU layer fields.
    Matches the former PacketDetailPanel.show_packet() right-side output.
    """
    lines: list[str] = []

    # Raw Hex Dump
    lines.append("  ─── Raw Bytes ───")
    lines.extend(_hex_dump(bytes.fromhex(packet.raw_hex)))
    lines.append("")

    # BVLC Layer
    lines.append("  ─── BVLC Layer ───")
    if packet.bvlc:
        b = packet.bvlc
        lines.append(f"  Type:          0x{b.type:02X} (BACnet/IPv4)")
        lines.append(f"  Function:      0x{b.function:02X} ({b.function_name})")
        lines.append(f"  Length:        {b.length} bytes")
        if b.originating_ip:
            lines.append(f"  Originator:    {b.originating_ip}:{b.originating_port}")
        if b.result_code is not None:
            lines.append(
                f"  Result:        0x{b.result_code:04X}"
                f" ({b.result_name or 'Unknown'})"
            )
        if b.ttl is not None:
            lines.append(f"  TTL:           {b.ttl}s")
    else:
        lines.append("  (not decoded)")
    lines.append("")

    # NPDU Layer
    lines.append("  ─── NPDU Layer ───")
    if packet.npdu:
        n = packet.npdu
        lines.append(f"  Version:       0x{n.version:02X}")
        lines.append(f"  Message Type:  {'Network' if n.is_network_message else 'APDU'}")
        lines.append(f"  Expecting Reply: {n.expecting_reply}")
        lines.append(f"  Priority:      {n.priority} ({n.priority_name})")
        if n.destination_network is not None:
            dnet = n.destination_network
            dnet_str = "Broadcast-All" if dnet == 0xFFFF else str(dnet)
            lines.append(f"  Dest Network:  {dnet_str}")
            if n.destination_address:
                lines.append(f"  Dest Address:  {n.destination_address}")
        if n.source_network is not None:
            lines.append(f"  Src Network:   {n.source_network}")
            if n.source_address:
                lines.append(f"  Src Address:   {n.source_address}")
        if n.hop_count is not None:
            lines.append(f"  Hop Count:     {n.hop_count}")
        if n.is_network_message:
            lines.append(
                f"  Net Msg Type:  0x{n.network_message_type:02X}"
                f" ({n.network_message_name})"
            )
            if n.reject_reason is not None:
                lines.append(
                    f"  Reject Reason: {n.reject_reason} ({n.reject_reason_name})"
                )
            if n.vendor_id is not None:
                lines.append(f"  Vendor ID:     {n.vendor_id}")
    else:
        lines.append("  (not decoded)")

    return "\n".join(lines)


def _hex_dump(data: bytes, width: int = 16) -> list[str]:
    """Format bytes as a hex dump (offset | hex bytes)."""
    lines: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        lines.append(f"  {offset:04X}  {hex_part}")
    return lines


def inspect_packet_dict(packet: ParsedPacket) -> dict:
    """Serialize a full packet inspection as a dictionary for JSON/REST output.

    Includes all layers with all fields, suitable for the packet detail view.
    """
    result: dict = {
        "id": packet.id,
        "timestamp": packet.timestamp,
        "length": packet.length,
        "source_ip": packet.source_ip,
        "source_port": packet.source_port,
        "destination_ip": packet.destination_ip,
        "destination_port": packet.destination_port,
        "effective_source_ip": packet.effective_source_ip,
        "effective_source_port": packet.effective_source_port,
        "raw_hex": packet.raw_hex,
        "parse_error": packet.parse_error,
    }

    if packet.bvlc:
        result["bvlc"] = packet.bvlc.model_dump()

    if packet.npdu:
        result["npdu"] = packet.npdu.model_dump()

    if packet.apdu:
        result["apdu"] = packet.apdu.model_dump()

    return result
