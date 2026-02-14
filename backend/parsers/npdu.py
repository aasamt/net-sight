"""NPDU (Network Protocol Data Unit) layer parser.

Decodes the NPDU header following the BVLC layer.
Returns an NPDUMessage model and the remaining bytes (APDU or network message data).

Wire format:
  Byte 0:   Version (always 0x01)
  Byte 1:   Control byte (bit flags)
  Byte 2+:  Optional DNET(2) + DLEN(1) + DADR(DLEN) + SNET(2) + SLEN(1) + SADR(SLEN) + HopCount(1)
  Last:     Message type (1 byte, if network layer message) + optional vendor ID (2 bytes)

Control byte flags:
  Bit 7 (0x80): 1 = network layer message, 0 = APDU follows
  Bit 5 (0x20): DNET/DADR/Hop Count present
  Bit 3 (0x08): SNET/SADR present
  Bit 2 (0x04): Expecting reply
  Bit 1-0 (0x03): Network priority
"""

from __future__ import annotations

import logging
import struct

from backend.models.npdu import (
    NETWORK_MESSAGE_TYPES,
    NETWORK_PRIORITIES,
    NETWORK_REJECT_REASONS,
    NPDUMessage,
)

logger = logging.getLogger(__name__)

NPDU_VERSION = 0x01


def parse_npdu(data: bytes) -> tuple[NPDUMessage, bytes]:
    """Parse the NPDU layer from bytes following the BVLC header.

    Args:
        data: Bytes starting at the NPDU header.

    Returns:
        Tuple of (NPDUMessage, remaining_bytes) where remaining_bytes
        is the APDU portion (or network message data).

    Raises:
        ValueError: If data is too short or has invalid NPDU version.
    """
    if len(data) < 2:
        raise ValueError(f"NPDU data too short: {len(data)} bytes (need >= 2)")

    version = data[0]
    if version != NPDU_VERSION:
        raise ValueError(f"Invalid NPDU version: 0x{version:02X} (expected 0x{NPDU_VERSION:02X})")

    control = data[1]
    is_network_message = bool(control & 0x80)
    has_dnet = bool(control & 0x20)
    has_snet = bool(control & 0x08)
    expecting_reply = bool(control & 0x04)
    priority = control & 0x03
    priority_name = NETWORK_PRIORITIES.get(priority, f"Unknown-{priority}")

    msg = NPDUMessage(
        version=version,
        is_network_message=is_network_message,
        expecting_reply=expecting_reply,
        priority=priority,
        priority_name=priority_name,
    )

    offset = 2

    # Parse destination address (DNET + DLEN + DADR)
    if has_dnet:
        if len(data) < offset + 3:
            raise ValueError("NPDU too short for destination network fields")

        dnet = struct.unpack("!H", data[offset : offset + 2])[0]
        offset += 2

        dlen = data[offset]
        offset += 1

        dadr = ""
        if dlen > 0:
            if len(data) < offset + dlen:
                raise ValueError("NPDU too short for destination address")
            dadr = data[offset : offset + dlen].hex()
            offset += dlen

        msg.destination_network = dnet
        msg.destination_address = dadr if dlen > 0 else None  # Empty = broadcast

    # Parse source address (SNET + SLEN + SADR)
    if has_snet:
        if len(data) < offset + 3:
            raise ValueError("NPDU too short for source network fields")

        snet = struct.unpack("!H", data[offset : offset + 2])[0]
        offset += 2

        slen = data[offset]
        offset += 1

        sadr = ""
        if slen > 0:
            if len(data) < offset + slen:
                raise ValueError("NPDU too short for source address")
            sadr = data[offset : offset + slen].hex()
            offset += slen

        msg.source_network = snet
        msg.source_address = sadr

    # Hop count (present only if DNET is present)
    if has_dnet:
        if len(data) < offset + 1:
            raise ValueError("NPDU too short for hop count")
        msg.hop_count = data[offset]
        offset += 1

    # Network layer message type (if bit 7 of control set)
    if is_network_message:
        if len(data) < offset + 1:
            raise ValueError("NPDU too short for network message type")

        msg_type = data[offset]
        offset += 1

        msg.network_message_type = msg_type
        msg.network_message_name = NETWORK_MESSAGE_TYPES.get(
            msg_type,
            f"Vendor-Proprietary-0x{msg_type:02X}" if msg_type >= 0x80
            else f"Reserved-0x{msg_type:02X}",
        )

        # Vendor ID present for proprietary messages (type >= 0x80)
        if msg_type >= 0x80:
            if len(data) >= offset + 2:
                msg.vendor_id = struct.unpack("!H", data[offset : offset + 2])[0]
                offset += 2

        # Parse reject reason for Reject-Message-To-Network (type 0x03)
        if msg_type == 0x03 and len(data) >= offset + 1:
            reject_reason = data[offset]
            msg.reject_reason = reject_reason
            msg.reject_reason_name = NETWORK_REJECT_REASONS.get(
                reject_reason, f"Unknown-{reject_reason}"
            )
            offset += 1

    remaining = data[offset:]
    return msg, remaining
