"""Who-Is broadcast sender for BACnet/IP.

Constructs and sends a BACnet Who-Is broadcast packet on UDP port 47808.
Supports optional device instance range limits.

Who-Is packet structure (global broadcast, no range):
  BVLC:  81 0B 00 0C          (Original-Broadcast-NPDU, length 12)
  NPDU:  01 20 FF FF 00 FF    (version 1, broadcast, hop count 255)
  APDU:  10 08                (Unconfirmed-Request, Who-Is service=8)

With device range (context tags 0 and 1):
  APDU:  10 08 09 XX 19 YY    (+ context-tag 0 = low limit, tag 1 = high limit)
"""

from __future__ import annotations

import logging
import socket
import struct

logger = logging.getLogger(__name__)

BACNET_PORT = 47808
BROADCAST_ADDR = "255.255.255.255"


def _encode_context_unsigned(tag_number: int, value: int) -> bytes:
    """Encode a BACnet context-tagged unsigned integer.

    Uses the minimum number of bytes needed to represent the value.

    Args:
        tag_number: Context tag number (0 or 1 for Who-Is range).
        value: Unsigned integer value to encode.

    Returns:
        Encoded bytes: tag byte + value bytes.
    """
    if value <= 0xFF:
        length = 1
        val_bytes = struct.pack("!B", value)
    elif value <= 0xFFFF:
        length = 2
        val_bytes = struct.pack("!H", value)
    elif value <= 0xFFFFFF:
        length = 3
        val_bytes = struct.pack("!I", value)[1:]  # 3 bytes from big-endian uint32
    else:
        length = 4
        val_bytes = struct.pack("!I", value)

    # Context tag byte: upper nibble = tag number, bit 3 = 1 (context), lower 3 = length
    tag_byte = (tag_number << 4) | 0x08 | (length & 0x07)
    return struct.pack("!B", tag_byte) + val_bytes


def build_whois_packet(
    low_limit: int | None = None,
    high_limit: int | None = None,
) -> bytes:
    """Build a complete BACnet/IP Who-Is broadcast packet (BVLC + NPDU + APDU).

    Args:
        low_limit: Optional low device instance limit (0–4194303).
        high_limit: Optional high device instance limit (0–4194303).
            Both must be provided together, or neither.

    Returns:
        Complete BACnet/IP UDP payload ready to send.

    Raises:
        ValueError: If only one of low/high is specified, or values are out of range.
    """
    if (low_limit is None) != (high_limit is None):
        raise ValueError("Both low_limit and high_limit must be specified, or neither")

    if low_limit is not None and high_limit is not None:
        if not (0 <= low_limit <= 4194303):
            raise ValueError(f"low_limit out of range: {low_limit} (0–4194303)")
        if not (0 <= high_limit <= 4194303):
            raise ValueError(f"high_limit out of range: {high_limit} (0–4194303)")
        if low_limit > high_limit:
            raise ValueError(
                f"low_limit ({low_limit}) must be <= high_limit ({high_limit})"
            )

    # --- APDU: Unconfirmed-Request, service choice = Who-Is (8) ---
    apdu = bytes([0x10, 0x08])  # PDU type 1 (unconfirmed), service 8 (Who-Is)

    if low_limit is not None and high_limit is not None:
        apdu += _encode_context_unsigned(0, low_limit)   # context tag 0: low limit
        apdu += _encode_context_unsigned(1, high_limit)   # context tag 1: high limit

    # --- NPDU: BACnet network layer (global broadcast) ---
    npdu = bytes([
        0x01,  # Version 1
        0x20,  # Control: broadcast (bit 5 = DNET present)
        0xFF, 0xFF,  # DNET = 65535 (global broadcast)
        0x00,  # DLEN = 0 (broadcast, no specific address)
        0xFF,  # Hop count = 255
    ])

    # --- BVLC: Original-Broadcast-NPDU (function 0x0B) ---
    payload = npdu + apdu
    bvlc_length = 4 + len(payload)
    bvlc = struct.pack("!BBH", 0x81, 0x0B, bvlc_length)

    return bvlc + payload


def send_whois(
    interface_ip: str | None = None,
    low_limit: int | None = None,
    high_limit: int | None = None,
) -> str:
    """Send a Who-Is broadcast on the BACnet/IP port.

    Args:
        interface_ip: Local IP address to bind to. If None, binds to 0.0.0.0.
        low_limit: Optional low device instance range limit.
        high_limit: Optional high device instance range limit.

    Returns:
        Human-readable status message.
    """
    try:
        packet = build_whois_packet(low_limit, high_limit)
    except ValueError as e:
        return f"Error: {e}"

    bind_ip = interface_ip or "0.0.0.0"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((bind_ip, 0))
        except OSError:
            # Fallback to any interface if specific bind fails
            sock.bind(("0.0.0.0", 0))

        sock.sendto(packet, (BROADCAST_ADDR, BACNET_PORT))
        sock.close()

        range_info = ""
        if low_limit is not None and high_limit is not None:
            range_info = f" (range {low_limit}–{high_limit})"

        msg = f"Who-Is broadcast sent{range_info} via {bind_ip} → {BROADCAST_ADDR}:{BACNET_PORT}"
        logger.info(msg)
        return msg

    except PermissionError:
        msg = "Permission denied — broadcast may require elevated privileges"
        logger.error(msg)
        return f"Error: {msg}"
    except OSError as e:
        msg = f"Network error: {e}"
        logger.error(msg)
        return f"Error: {msg}"
