"""BVLC (BACnet Virtual Link Control) layer parser.

Decodes the 4+ byte BVLC header at the start of every BACnet/IP UDP payload.
Returns a BVLCMessage model and the remaining bytes (NPDU + APDU).

Wire format:
  Byte 0:   Type (always 0x81 for BACnet/IPv4)
  Byte 1:   Function code (0x00–0x0C)
  Byte 2-3: Total BVLC message length (big-endian)
  Byte 4+:  Function-specific data, then NPDU+APDU
"""

from __future__ import annotations

import logging
import struct

from backend.models.bvlc import BVLC_FUNCTIONS, BVLC_RESULT_CODES, BVLCMessage

logger = logging.getLogger(__name__)

# BACnet/IPv4 type constant
BVLC_TYPE_IPV4 = 0x81

# BVLC header is always 4 bytes minimum
BVLC_HEADER_SIZE = 4

# Forwarded-NPDU has a 6-byte originating address after the 4-byte header
FORWARDED_NPDU_EXTRA = 6  # 4 bytes IP + 2 bytes port


def parse_bvlc(data: bytes) -> tuple[BVLCMessage, bytes]:
    """Parse the BVLC layer from raw BACnet/IP UDP payload.

    Args:
        data: Raw UDP payload bytes (starts with BVLC header).

    Returns:
        Tuple of (BVLCMessage, remaining_bytes) where remaining_bytes
        is the NPDU+APDU portion after the BVLC header.

    Raises:
        ValueError: If data is too short or has invalid BVLC type.
    """
    if len(data) < BVLC_HEADER_SIZE:
        raise ValueError(f"BVLC data too short: {len(data)} bytes (need >= {BVLC_HEADER_SIZE})")

    bvlc_type = data[0]
    if bvlc_type != BVLC_TYPE_IPV4:
        raise ValueError(f"Invalid BVLC type: 0x{bvlc_type:02X} (expected 0x{BVLC_TYPE_IPV4:02X})")

    function_code = data[1]
    length = struct.unpack("!H", data[2:4])[0]
    function_name = BVLC_FUNCTIONS.get(function_code, f"Unknown-0x{function_code:02X}")

    msg = BVLCMessage(
        type=bvlc_type,
        function=function_code,
        function_name=function_name,
        length=length,
    )

    # Determine where NPDU data starts based on function type
    npdu_offset = BVLC_HEADER_SIZE

    if function_code == 0x00:
        # BVLC-Result: 2-byte result code after header
        if len(data) >= 6:
            result_code = struct.unpack("!H", data[4:6])[0]
            msg.result_code = result_code
            msg.result_name = BVLC_RESULT_CODES.get(
                result_code, f"Unknown-0x{result_code:04X}"
            )
        # BVLC-Result has no NPDU payload
        return msg, b""

    elif function_code == 0x04:
        # Forwarded-NPDU: 6-byte originating address (4 IP + 2 port) after header
        if len(data) >= BVLC_HEADER_SIZE + FORWARDED_NPDU_EXTRA:
            ip_bytes = data[4:8]
            port = struct.unpack("!H", data[8:10])[0]
            msg.originating_ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
            msg.originating_port = port
            npdu_offset = BVLC_HEADER_SIZE + FORWARDED_NPDU_EXTRA
        else:
            raise ValueError(
                f"Forwarded-NPDU too short for originating address: {len(data)} bytes"
            )

    elif function_code == 0x05:
        # Register-Foreign-Device: 2-byte TTL after header
        if len(data) >= 6:
            msg.ttl = struct.unpack("!H", data[4:6])[0]
        # No NPDU payload
        return msg, b""

    elif function_code in (0x01, 0x02, 0x06, 0x08):
        # Write-BDT, Read-BDT, Read-FDT, Delete-FDT-Entry — management messages
        # These have their own data formats but no NPDU
        return msg, b""

    elif function_code == 0x03:
        # Read-BDT-Ack — contains BDT entries, no NPDU
        return msg, b""

    elif function_code == 0x07:
        # Read-FDT-Ack — contains FDT entries, no NPDU
        return msg, b""

    elif function_code in (0x09, 0x0A, 0x0B):
        # Distribute-Broadcast, Original-Unicast, Original-Broadcast
        # NPDU follows immediately after 4-byte header
        npdu_offset = BVLC_HEADER_SIZE

    remaining = data[npdu_offset:]
    return msg, remaining
