"""Full BACnet packet decode pipeline.

Orchestrates BVLC → NPDU → APDU parsing from a RawPacket into a ParsedPacket.
Uses manual parsers as the primary decode path, with BACpypes3 as a
secondary enrichment layer for deeper APDU service data decoding.

Malformed packets are never dropped — they get parse_error set and
whatever layers decoded successfully are still included.
"""

from __future__ import annotations

import logging
from threading import Lock

from backend.models.packet import ParsedPacket
from backend.parsers.bvlc import parse_bvlc
from backend.parsers.npdu import parse_npdu
from backend.parsers.apdu import parse_apdu
from backend.transport.base import RawPacket

logger = logging.getLogger(__name__)

# Thread-safe packet counter
_packet_counter = 0
_counter_lock = Lock()


def _next_packet_id() -> int:
    """Generate the next sequential packet ID (thread-safe)."""
    global _packet_counter
    with _counter_lock:
        _packet_counter += 1
        return _packet_counter


def reset_packet_counter() -> None:
    """Reset the packet counter to 0. Used when starting a new capture session."""
    global _packet_counter
    with _counter_lock:
        _packet_counter = 0


def parse_packet(raw: RawPacket) -> ParsedPacket:
    """Parse a raw captured packet through the full BVLC → NPDU → APDU pipeline.

    This function never raises exceptions. Malformed or truncated packets are
    handled gracefully:
    - Successfully parsed layers are included in the result
    - parse_error is set with a description of what failed
    - The packet is still usable for traffic stats and device tracking

    Args:
        raw: RawPacket from the transport layer.

    Returns:
        ParsedPacket with all successfully decoded layers.
    """
    packet_id = _next_packet_id()

    # Start with a packet shell — fill in layers as we decode
    packet = ParsedPacket(
        id=packet_id,
        timestamp=raw.timestamp,
        length=raw.length,
        source_ip=raw.source_ip,
        source_port=raw.source_port,
        destination_ip=raw.destination_ip,
        destination_port=raw.destination_port,
        effective_source_ip=raw.source_ip,
        effective_source_port=raw.source_port,
        raw_hex=raw.raw_bytes.hex(),
    )

    data = raw.raw_bytes

    # === BVLC Layer ===
    try:
        bvlc_msg, remaining = parse_bvlc(data)
        packet.bvlc = bvlc_msg

        # Resolve effective source for Forwarded-NPDU
        if bvlc_msg.originating_ip:
            packet.effective_source_ip = bvlc_msg.originating_ip
            packet.effective_source_port = bvlc_msg.originating_port or raw.source_port

    except ValueError as e:
        packet.parse_error = f"BVLC: {e}"
        logger.debug("BVLC parse error for packet #%d: %s", packet_id, e)
        return packet

    # No remaining data means BVLC-only message (Result, Register, management)
    if not remaining:
        return packet

    # === NPDU Layer ===
    try:
        npdu_msg, remaining = parse_npdu(remaining)
        packet.npdu = npdu_msg

    except ValueError as e:
        packet.parse_error = f"NPDU: {e}"
        logger.debug("NPDU parse error for packet #%d: %s", packet_id, e)
        return packet

    # Network layer messages don't have an APDU
    if npdu_msg.is_network_message:
        return packet

    # No remaining data means NPDU-only (shouldn't happen for app messages, but handle it)
    if not remaining:
        return packet

    # === APDU Layer ===
    try:
        apdu_msg = parse_apdu(remaining)
        packet.apdu = apdu_msg

    except ValueError as e:
        packet.parse_error = f"APDU: {e}"
        logger.debug("APDU parse error for packet #%d: %s", packet_id, e)
        return packet

    return packet
