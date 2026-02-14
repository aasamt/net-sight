"""APDU (Application Protocol Data Unit) layer parser.

Decodes the APDU following the NPDU layer. Only present when the NPDU
control byte indicates an application message (bit 7 = 0).

PDU type is encoded in the upper nibble of the first byte:
  0 = Confirmed-Request, 1 = Unconfirmed-Request, 2 = Simple-ACK,
  3 = Complex-ACK, 4 = Segment-ACK, 5 = Error, 6 = Reject, 7 = Abort

Each PDU type has a different header format. Service choice and invoke ID
positions vary by type.
"""

from __future__ import annotations

import logging
import struct

from backend.models.apdu import (
    ABORT_REASONS,
    CONFIRMED_SERVICES,
    ERROR_CLASSES,
    OBJECT_TYPES,
    PDU_TYPES,
    PROPERTY_IDENTIFIERS,
    REJECT_REASONS,
    SEGMENTATION_VALUES,
    UNCONFIRMED_SERVICES,
    APDUMessage,
    IAmFields,
    ObjectIdentifier,
    WhoIsRange,
)

logger = logging.getLogger(__name__)


def decode_object_identifier(value: int) -> ObjectIdentifier:
    """Decode a 32-bit BACnet object identifier.

    Upper 10 bits = object type, lower 22 bits = instance number.

    Args:
        value: 32-bit unsigned integer.

    Returns:
        ObjectIdentifier with type and instance.
    """
    object_type = (value >> 22) & 0x3FF
    instance = value & 0x3FFFFF
    type_name = OBJECT_TYPES.get(object_type, f"Proprietary-{object_type}")
    return ObjectIdentifier(
        object_type=object_type,
        object_type_name=type_name,
        instance=instance,
    )


def _parse_confirmed_request(data: bytes) -> APDUMessage:
    """Parse a Confirmed-Service-Request PDU (type 0).

    Header layout:
      Byte 0: PDU type (0x0X) + flags (SEG=0x08, MOR=0x04, SA=0x02)
      Byte 1: max-segments (upper nibble) + max-APDU-length (lower nibble)
      Byte 2: invoke ID
      Byte 3-4: sequence-number + proposed-window-size (if segmented)
      Next: service choice
    """
    if len(data) < 4:
        raise ValueError(f"Confirmed-Request too short: {len(data)} bytes")

    flags = data[0]
    segmented = bool(flags & 0x08)
    more_follows = bool(flags & 0x04)
    segmented_accepted = bool(flags & 0x02)

    max_segs_raw = (data[1] >> 4) & 0x07
    max_apdu_raw = data[1] & 0x0F

    invoke_id = data[2]

    offset = 3
    sequence_number = None
    window_size = None

    if segmented:
        if len(data) < 5:
            raise ValueError("Confirmed-Request too short for segmentation fields")
        sequence_number = data[3]
        window_size = data[4]
        offset = 5

    if len(data) <= offset:
        raise ValueError("Confirmed-Request too short for service choice")

    service_choice = data[offset]
    service_name = CONFIRMED_SERVICES.get(service_choice, f"Unknown-{service_choice}")

    msg = APDUMessage(
        pdu_type=0,
        pdu_type_name=PDU_TYPES[0],
        service_choice=service_choice,
        service_name=service_name,
        is_confirmed=True,
        invoke_id=invoke_id,
        segmented=segmented,
        more_follows=more_follows,
        sequence_number=sequence_number,
        window_size=window_size,
        max_segments=max_segs_raw,
        max_apdu_length=max_apdu_raw,
    )

    # Store and parse service data
    service_data = data[offset + 1 :]
    if service_data:
        msg.service_data_hex = service_data.hex()
    _try_extract_object_id(msg, service_data)
    _try_extract_property_id(msg, service_data)

    return msg


def _parse_unconfirmed_request(data: bytes) -> APDUMessage:
    """Parse an Unconfirmed-Service-Request PDU (type 1).

    Header layout:
      Byte 0: 0x10
      Byte 1: service choice
    """
    if len(data) < 2:
        raise ValueError(f"Unconfirmed-Request too short: {len(data)} bytes")

    service_choice = data[1]
    service_name = UNCONFIRMED_SERVICES.get(service_choice, f"Unknown-{service_choice}")

    msg = APDUMessage(
        pdu_type=1,
        pdu_type_name=PDU_TYPES[1],
        service_choice=service_choice,
        service_name=service_name,
        is_confirmed=False,
    )

    # Store service data payload
    service_data = data[2:]
    if service_data:
        msg.service_data_hex = service_data.hex()

    # Extract object identifier from service data (e.g., I-Am has device object ID)
    _try_extract_object_id(msg, service_data)

    # Service-specific decoding
    if service_choice == 0:  # I-Am
        _try_extract_iam_fields(msg, service_data)
    elif service_choice == 8:  # Who-Is
        _try_extract_whois_range(msg, service_data)

    return msg


def _parse_simple_ack(data: bytes) -> APDUMessage:
    """Parse a Simple-ACK PDU (type 2).

    Header layout:
      Byte 0: 0x20
      Byte 1: invoke ID
      Byte 2: service ACK choice
    """
    if len(data) < 3:
        raise ValueError(f"Simple-ACK too short: {len(data)} bytes")

    invoke_id = data[1]
    service_choice = data[2]
    service_name = CONFIRMED_SERVICES.get(service_choice, f"Unknown-{service_choice}")

    return APDUMessage(
        pdu_type=2,
        pdu_type_name=PDU_TYPES[2],
        service_choice=service_choice,
        service_name=service_name,
        is_confirmed=True,
        invoke_id=invoke_id,
    )


def _parse_complex_ack(data: bytes) -> APDUMessage:
    """Parse a Complex-ACK PDU (type 3).

    Header layout:
      Byte 0: 0x30 + flags (SEG=0x08, MOR=0x04)
      Byte 1: invoke ID
      Byte 2-3: sequence-number + proposed-window-size (if segmented)
      Next: service ACK choice
    """
    if len(data) < 3:
        raise ValueError(f"Complex-ACK too short: {len(data)} bytes")

    flags = data[0]
    segmented = bool(flags & 0x08)
    more_follows = bool(flags & 0x04)

    invoke_id = data[1]

    offset = 2
    sequence_number = None
    window_size = None

    if segmented:
        if len(data) < 5:
            raise ValueError("Complex-ACK too short for segmentation fields")
        sequence_number = data[2]
        window_size = data[3]
        offset = 4

    if len(data) <= offset:
        raise ValueError("Complex-ACK too short for service choice")

    service_choice = data[offset]
    service_name = CONFIRMED_SERVICES.get(service_choice, f"Unknown-{service_choice}")

    msg = APDUMessage(
        pdu_type=3,
        pdu_type_name=PDU_TYPES[3],
        service_choice=service_choice,
        service_name=service_name,
        is_confirmed=True,
        invoke_id=invoke_id,
        segmented=segmented,
        more_follows=more_follows,
        sequence_number=sequence_number,
        window_size=window_size,
    )

    # Store and parse ACK service data
    service_data = data[offset + 1 :]
    if service_data:
        msg.service_data_hex = service_data.hex()
    _try_extract_object_id(msg, service_data)
    _try_extract_property_id(msg, service_data)

    return msg


def _parse_segment_ack(data: bytes) -> APDUMessage:
    """Parse a Segment-ACK PDU (type 4).

    Header layout:
      Byte 0: 0x40 + flags (NAK=0x02, SRV=0x01)
      Byte 1: invoke ID
      Byte 2: sequence number
      Byte 3: actual window size
    """
    if len(data) < 4:
        raise ValueError(f"Segment-ACK too short: {len(data)} bytes")

    invoke_id = data[1]
    sequence_number = data[2]
    window_size = data[3]

    return APDUMessage(
        pdu_type=4,
        pdu_type_name=PDU_TYPES[4],
        invoke_id=invoke_id,
        sequence_number=sequence_number,
        window_size=window_size,
    )


def _parse_error(data: bytes) -> APDUMessage:
    """Parse an Error PDU (type 5).

    Header layout:
      Byte 0: 0x50
      Byte 1: invoke ID
      Byte 2: service choice
      Byte 3+: error class + error code (ASN.1 encoded)
    """
    if len(data) < 3:
        raise ValueError(f"Error PDU too short: {len(data)} bytes")

    invoke_id = data[1]
    service_choice = data[2]
    service_name = CONFIRMED_SERVICES.get(service_choice, f"Unknown-{service_choice}")

    msg = APDUMessage(
        pdu_type=5,
        pdu_type_name=PDU_TYPES[5],
        service_choice=service_choice,
        service_name=service_name,
        is_confirmed=True,
        invoke_id=invoke_id,
    )

    # Try to extract error class and code from ASN.1 encoded data
    error_data = data[3:]
    _try_extract_error(msg, error_data)

    return msg


def _parse_reject(data: bytes) -> APDUMessage:
    """Parse a Reject PDU (type 6).

    Header layout:
      Byte 0: 0x60
      Byte 1: invoke ID
      Byte 2: reject reason
    """
    if len(data) < 3:
        raise ValueError(f"Reject PDU too short: {len(data)} bytes")

    invoke_id = data[1]
    reject_reason = data[2]
    reject_reason_name = REJECT_REASONS.get(reject_reason, f"Unknown-{reject_reason}")

    return APDUMessage(
        pdu_type=6,
        pdu_type_name=PDU_TYPES[6],
        invoke_id=invoke_id,
        reject_reason=reject_reason,
        reject_reason_name=reject_reason_name,
    )


def _parse_abort(data: bytes) -> APDUMessage:
    """Parse an Abort PDU (type 7).

    Header layout:
      Byte 0: 0x70 + SRV flag (0x01)
      Byte 1: invoke ID
      Byte 2: abort reason
    """
    if len(data) < 3:
        raise ValueError(f"Abort PDU too short: {len(data)} bytes")

    invoke_id = data[1]
    abort_reason = data[2]
    abort_reason_name = ABORT_REASONS.get(abort_reason, f"Unknown-{abort_reason}")

    return APDUMessage(
        pdu_type=7,
        pdu_type_name=PDU_TYPES[7],
        invoke_id=invoke_id,
        abort_reason=abort_reason,
        abort_reason_name=abort_reason_name,
    )


# PDU type → parser function dispatch
_PDU_PARSERS = {
    0: _parse_confirmed_request,
    1: _parse_unconfirmed_request,
    2: _parse_simple_ack,
    3: _parse_complex_ack,
    4: _parse_segment_ack,
    5: _parse_error,
    6: _parse_reject,
    7: _parse_abort,
}


def parse_apdu(data: bytes) -> APDUMessage:
    """Parse the APDU layer from bytes following the NPDU.

    Args:
        data: Bytes starting at the APDU header.

    Returns:
        APDUMessage with decoded fields.

    Raises:
        ValueError: If data is too short or has unknown PDU type.
    """
    if len(data) < 1:
        raise ValueError("APDU data is empty")

    pdu_type = (data[0] >> 4) & 0x0F

    parser = _PDU_PARSERS.get(pdu_type)
    if parser is None:
        raise ValueError(f"Unknown APDU PDU type: {pdu_type}")

    return parser(data)


def _try_extract_object_id(msg: APDUMessage, service_data: bytes) -> None:
    """Try to extract object identifier from APDU service data.

    Uses a best-effort approach to find context-tagged [0] object identifier
    in the service data. This is a simplified extraction that works for
    common services (ReadProperty, WriteProperty, I-Am, etc.).

    For I-Am (unconfirmed service 0): the object ID is the first 4 bytes
    as an application-tagged BACnetObjectIdentifier (tag 12).
    """
    if not service_data or len(service_data) < 4:
        return

    try:
        # I-Am response: first tag is application tag 12 (object identifier)
        if msg.pdu_type == 1 and msg.service_choice == 0:
            # I-Am: tag byte + length + 4 bytes object ID
            tag_byte = service_data[0]
            tag_number = (tag_byte >> 4) & 0x0F
            tag_class = (tag_byte >> 3) & 0x01  # 0 = application, 1 = context

            if tag_class == 0 and tag_number == 12:
                # Application tag 12 = BACnetObjectIdentifier, 4 bytes
                length_vt = tag_byte & 0x07
                if length_vt == 4 and len(service_data) >= 5:
                    obj_value = struct.unpack("!I", service_data[1:5])[0]
                    msg.object_identifier = decode_object_identifier(obj_value)
            return

        # Confirmed services with context tag [0] = objectIdentifier
        # ReadProperty, WriteProperty, etc.
        if msg.pdu_type in (0, 3) and service_data:
            tag_byte = service_data[0]
            tag_number = tag_byte >> 4
            tag_class = (tag_byte >> 3) & 0x01  # 1 = context tag

            if tag_class == 1 and tag_number == 0:
                # Context tag [0], typically 4 bytes for object ID
                length_vt = tag_byte & 0x07
                if length_vt == 4 and len(service_data) >= 5:
                    obj_value = struct.unpack("!I", service_data[1:5])[0]
                    msg.object_identifier = decode_object_identifier(obj_value)

    except Exception:
        # Best-effort extraction — don't fail the parse
        pass


def _try_extract_error(msg: APDUMessage, error_data: bytes) -> None:
    """Try to extract error class and code from ASN.1 encoded error data.

    BACnet errors are encoded as:
      Application tag 9 (enumerated) + error class
      Application tag 9 (enumerated) + error code
    """
    if not error_data or len(error_data) < 4:
        return

    try:
        offset = 0

        # Error class: application tag 9, usually 1 byte value
        tag_byte = error_data[offset]
        tag_number = (tag_byte >> 4) & 0x0F
        if tag_number == 9:  # Enumerated
            length_vt = tag_byte & 0x07
            offset += 1
            if length_vt > 0 and len(error_data) >= offset + length_vt:
                error_class = int.from_bytes(
                    error_data[offset : offset + length_vt], "big"
                )
                msg.error_class = error_class
                msg.error_class_name = ERROR_CLASSES.get(
                    error_class, f"Unknown-{error_class}"
                )
                offset += length_vt

        # Error code: application tag 9, usually 1 byte value
        if len(error_data) > offset:
            tag_byte = error_data[offset]
            tag_number = (tag_byte >> 4) & 0x0F
            if tag_number == 9:
                length_vt = tag_byte & 0x07
                offset += 1
                if length_vt > 0 and len(error_data) >= offset + length_vt:
                    error_code = int.from_bytes(
                        error_data[offset : offset + length_vt], "big"
                    )
                    msg.error_code = error_code

    except Exception:
        # Best-effort extraction
        pass


def _try_extract_property_id(msg: APDUMessage, service_data: bytes) -> None:
    """Try to extract the property identifier from service data.

    For ReadProperty/WriteProperty/ReadPropertyMultiple (services 12-16),
    the property identifier follows the object identifier as context tag [1].

    Layout after APDU header:
      [0] Object Identifier (4 bytes, context tag 0)
      [1] Property Identifier (1-4 bytes, context tag 1)
      [2] Property Array Index (optional, context tag 2)
    """
    if not service_data or len(service_data) < 7:
        return

    # Only for services that have property identifiers
    if msg.service_choice not in (12, 14, 15, 16):
        return

    try:
        offset = 0

        # Skip context tag [0] — object identifier (already parsed)
        tag_byte = service_data[offset]
        tag_number = tag_byte >> 4
        tag_class = (tag_byte >> 3) & 0x01
        if tag_class == 1 and tag_number == 0:
            length_vt = tag_byte & 0x07
            offset += 1 + length_vt
        else:
            return

        if offset >= len(service_data):
            return

        # Context tag [1] — property identifier (enumerated, 1-4 bytes)
        tag_byte = service_data[offset]
        tag_number = tag_byte >> 4
        tag_class = (tag_byte >> 3) & 0x01
        if tag_class == 1 and tag_number == 1:
            length_vt = tag_byte & 0x07
            offset += 1
            if length_vt > 0 and len(service_data) >= offset + length_vt:
                prop_id = int.from_bytes(
                    service_data[offset:offset + length_vt], "big"
                )
                msg.property_identifier = prop_id
                msg.property_name = PROPERTY_IDENTIFIERS.get(
                    prop_id, f"Proprietary-{prop_id}"
                )
                offset += length_vt

        # Optional context tag [2] — property array index
        if offset < len(service_data):
            tag_byte = service_data[offset]
            tag_number = tag_byte >> 4
            tag_class = (tag_byte >> 3) & 0x01
            if tag_class == 1 and tag_number == 2:
                length_vt = tag_byte & 0x07
                offset += 1
                if length_vt > 0 and len(service_data) >= offset + length_vt:
                    msg.property_array_index = int.from_bytes(
                        service_data[offset:offset + length_vt], "big"
                    )

    except Exception:
        pass


def _try_extract_iam_fields(msg: APDUMessage, service_data: bytes) -> None:
    """Try to extract I-Am service data fields.

    I-Am PDU service data layout (all application-tagged):
      - BACnetObjectIdentifier (tag 12, 4 bytes) — device object ID
      - Unsigned (tag 2) — max APDU length accepted
      - BACnetSegmentation (tag 9, 1 byte) — segmentation supported (enum 0-3)
      - Unsigned (tag 2) — vendor ID
    """
    if not service_data or len(service_data) < 10:
        return

    try:
        offset = 0

        # 1) Object identifier (tag 12, 4 bytes) — already parsed by _try_extract_object_id
        tag_byte = service_data[offset]
        tag_number = (tag_byte >> 4) & 0x0F
        if tag_number != 12:
            return
        length_vt = tag_byte & 0x07
        offset += 1 + length_vt  # skip tag + value

        # Extract device instance from the already-parsed object identifier
        device_instance = 0
        if msg.object_identifier:
            device_instance = msg.object_identifier.instance

        if offset >= len(service_data):
            return

        # 2) Max APDU length accepted (tag 2 = unsigned, variable length)
        tag_byte = service_data[offset]
        tag_number = (tag_byte >> 4) & 0x0F
        if tag_number != 2:
            return
        length_vt = tag_byte & 0x07
        offset += 1
        if len(service_data) < offset + length_vt:
            return
        max_apdu = int.from_bytes(
            service_data[offset:offset + length_vt], "big"
        )
        offset += length_vt

        if offset >= len(service_data):
            return

        # 3) Segmentation supported (tag 9 = enumerated, 1 byte)
        tag_byte = service_data[offset]
        tag_number = (tag_byte >> 4) & 0x0F
        if tag_number != 9:
            return
        length_vt = tag_byte & 0x07
        offset += 1
        if len(service_data) < offset + length_vt:
            return
        seg_value = int.from_bytes(
            service_data[offset:offset + length_vt], "big"
        )
        seg_name = SEGMENTATION_VALUES.get(seg_value, f"Unknown-{seg_value}")
        offset += length_vt

        if offset >= len(service_data):
            return

        # 4) Vendor ID (tag 2 = unsigned, variable length)
        tag_byte = service_data[offset]
        tag_number = (tag_byte >> 4) & 0x0F
        if tag_number != 2:
            return
        length_vt = tag_byte & 0x07
        offset += 1
        if len(service_data) < offset + length_vt:
            return
        vendor_id = int.from_bytes(
            service_data[offset:offset + length_vt], "big"
        )

        msg.iam_fields = IAmFields(
            device_instance=device_instance,
            max_apdu_length=max_apdu,
            segmentation_supported=seg_value,
            segmentation_name=seg_name,
            vendor_id=vendor_id,
        )

    except Exception:
        pass


def _try_extract_whois_range(msg: APDUMessage, service_data: bytes) -> None:
    """Try to extract Who-Is device instance range limits.

    Who-Is service data layout (context-tagged, optional):
      [0] low-limit  — unsigned integer
      [1] high-limit — unsigned integer

    If no service data, it's a global Who-Is (no range limits).
    """
    if not service_data or len(service_data) < 4:
        return

    try:
        offset = 0

        # Context tag [0] — low limit
        tag_byte = service_data[offset]
        tag_number = tag_byte >> 4
        tag_class = (tag_byte >> 3) & 0x01
        if tag_class != 1 or tag_number != 0:
            return
        length_vt = tag_byte & 0x07
        offset += 1
        if len(service_data) < offset + length_vt:
            return
        low_limit = int.from_bytes(
            service_data[offset:offset + length_vt], "big"
        )
        offset += length_vt

        if offset >= len(service_data):
            return

        # Context tag [1] — high limit
        tag_byte = service_data[offset]
        tag_number = tag_byte >> 4
        tag_class = (tag_byte >> 3) & 0x01
        if tag_class != 1 or tag_number != 1:
            return
        length_vt = tag_byte & 0x07
        offset += 1
        if len(service_data) < offset + length_vt:
            return
        high_limit = int.from_bytes(
            service_data[offset:offset + length_vt], "big"
        )

        msg.who_is_range = WhoIsRange(
            low_limit=low_limit,
            high_limit=high_limit,
        )

    except Exception:
        pass
