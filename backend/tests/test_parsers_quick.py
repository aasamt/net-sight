"""Comprehensive validation of Phase 3 parsers with varied BACnet/IP hex samples.

Each test case is a hand-crafted BACnet/IP packet with bytes verified against
the protocol spec. Tests exercise every major code path in the BVLC, NPDU,
APDU parsers and the full pipeline.
"""

import time
from backend.transport.base import RawPacket
from backend.parsers.pipeline import parse_packet, reset_packet_counter
from backend.parsers.bvlc import parse_bvlc
from backend.parsers.npdu import parse_npdu
from backend.parsers.apdu import parse_apdu

reset_packet_counter()
passed = 0
failed = 0


def make_raw(hex_str: str, src: str = "192.168.1.10", dst: str = "192.168.1.20") -> RawPacket:
    """Helper to build a RawPacket from a hex string."""
    data = bytes.fromhex(hex_str.replace(" ", ""))
    return RawPacket(
        timestamp=time.time(),
        raw_bytes=data,
        source_ip=src,
        source_port=47808,
        destination_ip=dst,
        destination_port=47808,
        length=len(data),
    )


def run_test(name: str, fn):
    """Run a test function and track pass/fail."""
    global passed, failed
    try:
        fn()
        passed += 1
        print(f"  PASS  {name}")
    except Exception as e:
        failed += 1
        print(f"  FAIL  {name}: {e}")


# Guard: only run the custom test runner when executed directly, not via pytest
_DIRECT_RUN = __name__ == "__main__"

# ─── GROUP 1: BVLC Function Types ────────────────────────────────────────────

if _DIRECT_RUN: print("\n── BVLC Function Types ──")


def test_original_broadcast():
    """BVLC 0x0B — Original-Broadcast-NPDU carrying Who-Is."""
    # 81 0B 000C | 01 20 FFFF 00 FF | 10 08
    pkt = parse_packet(make_raw("810B000C 0120FFFF00FF 1008", dst="192.168.1.255"))
    assert pkt.bvlc.function == 0x0B
    assert pkt.bvlc.function_name == "Original-Broadcast-NPDU"
    assert pkt.bvlc.length == 12
    assert pkt.npdu.destination_network == 0xFFFF
    assert pkt.apdu.service_name == "Who-Is"
    assert pkt.parse_error is None


def test_original_unicast():
    """BVLC 0x0A — Original-Unicast-NPDU carrying ReadProperty."""
    # 81 0A 0011 | 01 04 | 00 04 05 0C 0C00000001 1955
    pkt = parse_packet(make_raw("810A0011 0104 0004050C 0C000000011955"))
    assert pkt.bvlc.function == 0x0A
    assert pkt.bvlc.function_name == "Original-Unicast-NPDU"
    assert pkt.npdu.expecting_reply is True
    assert pkt.apdu.service_name == "ReadProperty"
    assert pkt.parse_error is None


def test_forwarded_npdu():
    """BVLC 0x04 — Forwarded-NPDU with originating IP extraction."""
    # 81 04 000E | C0A80114 BAC0 | 01 00 | 10 08
    pkt = parse_packet(make_raw("8104000E C0A80114BAC0 0100 1008", src="10.0.0.1"))
    assert pkt.bvlc.function == 0x04
    assert pkt.bvlc.originating_ip == "192.168.1.20"
    assert pkt.bvlc.originating_port == 47808
    assert pkt.effective_source_ip == "192.168.1.20"
    assert pkt.effective_source_port == 47808
    assert pkt.apdu.service_name == "Who-Is"
    assert pkt.parse_error is None


def test_bvlc_result_success():
    """BVLC 0x00 — BVLC-Result with Successful-Completion."""
    # 81 00 0006 0000
    pkt = parse_packet(make_raw("810000060000"))
    assert pkt.bvlc.function == 0x00
    assert pkt.bvlc.result_code == 0
    assert pkt.bvlc.result_name == "Successful-Completion"
    assert pkt.npdu is None
    assert pkt.apdu is None
    assert pkt.parse_error is None


def test_bvlc_result_nack():
    """BVLC 0x00 — BVLC-Result with Write-Broadcast-Distribution-Table-NAK."""
    # 81 00 0006 0020
    pkt = parse_packet(make_raw("810000060020"))
    assert pkt.bvlc.function == 0x00
    assert pkt.bvlc.result_code == 0x0020


def test_register_foreign_device():
    """BVLC 0x05 — Register-Foreign-Device with TTL=60s."""
    # 81 05 0006 003C
    pkt = parse_packet(make_raw("8105 0006 003C"))
    assert pkt.bvlc.function == 0x05
    assert pkt.bvlc.function_name == "Register-Foreign-Device"
    assert pkt.bvlc.ttl == 60
    assert pkt.npdu is None
    assert pkt.apdu is None
    assert pkt.parse_error is None


def test_distribute_broadcast():
    """BVLC 0x09 — Distribute-Broadcast carrying I-Am."""
    # 81 09 0014 | 01 00 | 10 00 C4020000C8 2205C4 9103 2178
    pkt = parse_packet(make_raw("810900140100 1000 C4020000C8 2205C4 9103 2178"))
    assert pkt.bvlc.function == 0x09
    assert pkt.bvlc.function_name == "Distribute-Broadcast-To-Network"
    assert pkt.apdu.service_name == "I-Am"
    assert pkt.parse_error is None


def test_read_bdt():
    """BVLC 0x02 — Read-BDT (management, no NPDU)."""
    # 81 02 0004
    pkt = parse_packet(make_raw("81020004"))
    assert pkt.bvlc.function == 0x02
    assert pkt.bvlc.function_name == "Read-BDT"
    assert pkt.npdu is None
    assert pkt.apdu is None
    assert pkt.parse_error is None


if _DIRECT_RUN:
    for fn in [
        test_original_broadcast, test_original_unicast, test_forwarded_npdu,
        test_bvlc_result_success, test_bvlc_result_nack, test_register_foreign_device,
        test_distribute_broadcast, test_read_bdt,
    ]:
        run_test(fn.__doc__.strip(), fn)


# ─── GROUP 2: NPDU Variations ────────────────────────────────────────────────

if _DIRECT_RUN: print("\n── NPDU Variations ──")


def test_npdu_simple():
    """NPDU — no DNET, no SNET, Normal priority."""
    pkt = parse_packet(make_raw("810A0008 0100 1008"))
    assert pkt.npdu.version == 1
    assert pkt.npdu.destination_network is None
    assert pkt.npdu.source_network is None
    assert pkt.npdu.expecting_reply is False
    assert pkt.npdu.priority == 0
    assert pkt.npdu.priority_name == "Normal"
    assert pkt.npdu.is_network_message is False


def test_npdu_dnet_broadcast():
    """NPDU — DNET=0xFFFF (global broadcast), DLEN=0, hop=255."""
    # 01 20 FFFF 00 FF
    pkt = parse_packet(make_raw("810B000C 0120 FFFF 00 FF 1008", dst="192.168.1.255"))
    assert pkt.npdu.destination_network == 0xFFFF
    assert pkt.npdu.destination_address is None  # DLEN=0 → broadcast
    assert pkt.npdu.hop_count == 255
    assert pkt.npdu.source_network is None


def test_npdu_dnet_with_address():
    """NPDU — DNET=10 with 1-byte DADR=0x05, hop=254."""
    # 01 20 000A 01 05 FE
    pkt = parse_packet(make_raw("810A000D 0120 000A 01 05 FE 1008"))
    assert pkt.npdu.destination_network == 10
    assert pkt.npdu.destination_address == "05"
    assert pkt.npdu.hop_count == 254
    assert pkt.npdu.source_network is None


def test_npdu_snet_only():
    """NPDU — SNET=20 with 1-byte SADR=0x0A, no DNET."""
    # 01 08 0014 01 0A
    pkt = parse_packet(make_raw("810A000D 0108 0014 01 0A 1008"))
    assert pkt.npdu.source_network == 20
    assert pkt.npdu.source_address == "0a"
    assert pkt.npdu.destination_network is None
    assert pkt.npdu.hop_count is None


def test_npdu_dnet_and_snet():
    """NPDU — DNET=10/DADR=05 + SNET=20/SADR=0A, hop=254."""
    # 01 28 000A 01 05 0014 01 0A FE
    pkt = parse_packet(make_raw("810A0011 0128 000A 01 05 0014 01 0A FE 1008"))
    assert pkt.npdu.destination_network == 10
    assert pkt.npdu.destination_address == "05"
    assert pkt.npdu.source_network == 20
    assert pkt.npdu.source_address == "0a"
    assert pkt.npdu.hop_count == 254
    assert pkt.apdu.service_name == "Who-Is"


def test_npdu_expecting_reply():
    """NPDU — expecting-reply flag set (control bit 2)."""
    # 01 04  (expecting_reply=True)
    pkt = parse_packet(make_raw("810A0008 0104 1008"))
    assert pkt.npdu.expecting_reply is True


def test_npdu_life_safety_priority():
    """NPDU — Life-Safety priority (priority=3, bits 0-1)."""
    # 01 03  (priority=3)
    pkt = parse_packet(make_raw("810A0008 0103 1008"))
    assert pkt.npdu.priority == 3
    assert pkt.npdu.priority_name == "Life-Safety"


def test_npdu_network_message_who_is_router():
    """NPDU — Network layer: Who-Is-Router-To-Network (type 0x00), no APDU."""
    # 01 80 00
    pkt = parse_packet(make_raw("810B0007 018000", dst="192.168.1.255"))
    assert pkt.npdu.is_network_message is True
    assert pkt.npdu.network_message_type == 0x00
    assert pkt.npdu.network_message_name == "Who-Is-Router-To-Network"
    assert pkt.apdu is None
    assert pkt.parse_error is None


def test_npdu_network_message_i_am_router():
    """NPDU — Network layer: I-Am-Router-To-Network (type 0x01)."""
    # 01 80 01 + 2-byte network (ignored as 'remaining')
    pkt = parse_packet(make_raw("810B0009 018001 000A", dst="192.168.1.255"))
    assert pkt.npdu.is_network_message is True
    assert pkt.npdu.network_message_type == 0x01
    assert pkt.npdu.network_message_name == "I-Am-Router-To-Network"
    assert pkt.apdu is None


def test_npdu_network_message_reject():
    """NPDU — Network layer: Reject-Message-To-Network (type 0x03) with reason."""
    # 01 80 03 02 (reject reason 2 = "Other-Error")
    pkt = parse_packet(make_raw("810B0008 018003 02", dst="192.168.1.255"))
    assert pkt.npdu.network_message_type == 0x03
    assert pkt.npdu.network_message_name == "Reject-Message-To-Network"
    assert pkt.npdu.reject_reason == 2


def test_npdu_3_byte_dadr():
    """NPDU — DNET with DLEN=3 (MS/TP 3-byte address)."""
    # 01 20 000F 03 010203 FE
    pkt = parse_packet(make_raw("810A0010 0120 000F 03 010203 FE 1008"))
    assert pkt.npdu.destination_network == 15
    assert pkt.npdu.destination_address == "010203"
    assert pkt.npdu.hop_count == 254


if _DIRECT_RUN:
    for fn in [
        test_npdu_simple, test_npdu_dnet_broadcast, test_npdu_dnet_with_address,
        test_npdu_snet_only, test_npdu_dnet_and_snet, test_npdu_expecting_reply,
        test_npdu_life_safety_priority, test_npdu_network_message_who_is_router,
        test_npdu_network_message_i_am_router, test_npdu_network_message_reject,
        test_npdu_3_byte_dadr,
    ]:
        run_test(fn.__doc__.strip(), fn)


# ─── GROUP 3: APDU PDU Types ─────────────────────────────────────────────────

if _DIRECT_RUN: print("\n── APDU PDU Types ──")


def test_unconfirmed_who_is():
    """APDU type 1 — Unconfirmed Who-Is (service 8)."""
    pkt = parse_packet(make_raw("810B0008 0100 1008", dst="192.168.1.255"))
    assert pkt.apdu.pdu_type == 1
    assert pkt.apdu.pdu_type_name == "Unconfirmed-Request"
    assert pkt.apdu.service_choice == 8
    assert pkt.apdu.service_name == "Who-Is"
    assert pkt.apdu.is_confirmed is False
    assert pkt.apdu.invoke_id is None


def test_unconfirmed_iam():
    """APDU type 1 — I-Am with Device:100 object ID extracted."""
    # 10 00 | C4 02000064 | 22 05 | C4 | 91 03 | 21 78
    pkt = parse_packet(make_raw("810B0014 0100 1000 C4020000642205C491032178"))
    assert pkt.apdu.service_name == "I-Am"
    assert pkt.apdu.object_identifier is not None
    assert pkt.apdu.object_identifier.object_type == 8  # Device
    assert pkt.apdu.object_identifier.object_type_name == "Device"
    assert pkt.apdu.object_identifier.instance == 100


def test_unconfirmed_who_has():
    """APDU type 1 — Who-Has (service 7)."""
    # 10 07
    pkt = parse_packet(make_raw("810B0008 0100 1007", dst="192.168.1.255"))
    assert pkt.apdu.pdu_type == 1
    assert pkt.apdu.service_name == "Who-Has"
    assert pkt.apdu.is_confirmed is False


def test_unconfirmed_time_sync():
    """APDU type 1 — TimeSynchronization (service 6) with date+time tags."""
    # 10 06 | A4 7E020C04 | B4 0A1E0000
    pkt = parse_packet(make_raw("810B0012 0100 1006 A47E020C04 B40A1E0000"))
    assert pkt.apdu.service_name == "TimeSynchronization"
    assert pkt.apdu.is_confirmed is False
    assert pkt.apdu.object_identifier is None  # No object ID in time sync


def test_unconfirmed_cov_notification():
    """APDU type 1 — UnconfirmedCOVNotification (service 2)."""
    # 10 02 + minimal service data
    pkt = parse_packet(make_raw("810A000A 0100 1002 0901"))
    assert pkt.apdu.pdu_type == 1
    assert pkt.apdu.service_name == "UnconfirmedCOVNotification"


def test_confirmed_readproperty():
    """APDU type 0 — Confirmed ReadProperty, Analog-Input:1, invoke=5."""
    # 00 04 05 0C | 0C 00000001 19 55
    pkt = parse_packet(make_raw("810A0011 0104 0004050C 0C000000011955"))
    assert pkt.apdu.pdu_type == 0
    assert pkt.apdu.pdu_type_name == "Confirmed-Request"
    assert pkt.apdu.service_name == "ReadProperty"
    assert pkt.apdu.invoke_id == 5
    assert pkt.apdu.is_confirmed is True
    assert pkt.apdu.segmented is False
    assert pkt.apdu.object_identifier.object_type_name == "Analog-Input"
    assert pkt.apdu.object_identifier.instance == 1


def test_confirmed_writeproperty():
    """APDU type 0 — Confirmed WriteProperty (service 15), invoke=10."""
    # 00 04 0A 0F | 0C 00400002 1955 3E 4442C80000 3F  (Analog-Output:2)
    pkt = parse_packet(make_raw(
        "810A001B 0104 00040A0F 0C004000021955 3E4442C800003F"
    ))
    assert pkt.apdu.pdu_type == 0
    assert pkt.apdu.service_name == "WriteProperty"
    assert pkt.apdu.invoke_id == 10
    assert pkt.apdu.object_identifier.object_type_name == "Analog-Output"
    assert pkt.apdu.object_identifier.instance == 2


def test_confirmed_subscribe_cov():
    """APDU type 0 — Confirmed SubscribeCOV (service 5), invoke=3."""
    # 00 04 03 05 | 09 01 1C 02000064
    pkt = parse_packet(make_raw("810A0011 0104 00040305 0901 1C02000064"))
    assert pkt.apdu.service_name == "SubscribeCOV"
    assert pkt.apdu.invoke_id == 3
    assert pkt.apdu.is_confirmed is True


def test_confirmed_cov_notification():
    """APDU type 0 — Confirmed COVNotification (service 1), invoke=1."""
    # 00 04 01 01 | 09 01 1C 020000C8
    pkt = parse_packet(make_raw("810A0011 0104 00040101 0901 1C020000C8"))
    assert pkt.apdu.service_name == "ConfirmedCOVNotification"
    assert pkt.apdu.invoke_id == 1


def test_confirmed_readproperty_multiple():
    """APDU type 0 — Confirmed ReadPropertyMultiple (service 14), invoke=7."""
    # 00 04 07 0E | 0C 00000001 1E 09 55 1F
    pkt = parse_packet(make_raw("810A0013 0104 0004070E 0C00000001 1E0955 1F"))
    assert pkt.apdu.service_name == "ReadPropertyMultiple"
    assert pkt.apdu.invoke_id == 7
    assert pkt.apdu.object_identifier.object_type_name == "Analog-Input"
    assert pkt.apdu.object_identifier.instance == 1


def test_simple_ack_writeproperty():
    """APDU type 2 — Simple-ACK for WriteProperty, invoke=3."""
    # 20 03 0F
    pkt = parse_packet(make_raw("810A0009 0100 20030F"))
    assert pkt.apdu.pdu_type == 2
    assert pkt.apdu.pdu_type_name == "Simple-ACK"
    assert pkt.apdu.invoke_id == 3
    assert pkt.apdu.service_name == "WriteProperty"
    assert pkt.apdu.is_confirmed is True


def test_simple_ack_subscribe_cov():
    """APDU type 2 — Simple-ACK for SubscribeCOV, invoke=12."""
    # 20 0C 05
    pkt = parse_packet(make_raw("810A0009 0100 200C05"))
    assert pkt.apdu.pdu_type == 2
    assert pkt.apdu.service_name == "SubscribeCOV"
    assert pkt.apdu.invoke_id == 12


def test_complex_ack_readproperty():
    """APDU type 3 — Complex-ACK ReadProperty, Analog-Input:1, invoke=5."""
    # 30 05 0C | 0C 00000001 1955 3E 4442C80000 3F
    pkt = parse_packet(make_raw("810A0017 0100 30050C 0C000000011955 3E4442C800003F"))
    assert pkt.apdu.pdu_type == 3
    assert pkt.apdu.pdu_type_name == "Complex-ACK"
    assert pkt.apdu.invoke_id == 5
    assert pkt.apdu.service_name == "ReadProperty"
    assert pkt.apdu.segmented is False
    assert pkt.apdu.object_identifier.object_type_name == "Analog-Input"
    assert pkt.apdu.object_identifier.instance == 1


def test_complex_ack_readproperty_multiple():
    """APDU type 3 — Complex-ACK ReadPropertyMultiple, invoke=7."""
    # 30 07 0E | 0C 00000001 1E0955 3E4442C800003F 1F
    pkt = parse_packet(make_raw(
        "810A001B 0100 30070E 0C00000001 1E0955 3E4442C800003F 1F"
    ))
    assert pkt.apdu.pdu_type == 3
    assert pkt.apdu.service_name == "ReadPropertyMultiple"
    assert pkt.apdu.invoke_id == 7


def test_segment_ack():
    """APDU type 4 — Segment-ACK, invoke=7, seq=3, window=5."""
    # 40 07 03 05
    pkt = parse_packet(make_raw("810A000A 0100 40070305"))
    assert pkt.apdu.pdu_type == 4
    assert pkt.apdu.pdu_type_name == "Segment-ACK"
    assert pkt.apdu.invoke_id == 7
    assert pkt.apdu.sequence_number == 3
    assert pkt.apdu.window_size == 5


def test_error_pdu():
    """APDU type 5 — Error for ReadProperty: Object / unknown-object."""
    # 50 05 0C | 91 01 91 1F
    pkt = parse_packet(make_raw("810A000D 0100 50050C 9101911F"))
    assert pkt.apdu.pdu_type == 5
    assert pkt.apdu.pdu_type_name == "Error"
    assert pkt.apdu.invoke_id == 5
    assert pkt.apdu.service_name == "ReadProperty"
    assert pkt.apdu.error_class == 1
    assert pkt.apdu.error_class_name == "Object"
    assert pkt.apdu.error_code == 31


def test_error_pdu_property_class():
    """APDU type 5 — Error for ReadProperty: Property / unknown-property."""
    # 50 08 0C | 91 02 91 20
    pkt = parse_packet(make_raw("810A000D 0100 50080C 91029120"))
    assert pkt.apdu.pdu_type == 5
    assert pkt.apdu.invoke_id == 8
    assert pkt.apdu.error_class == 2
    assert pkt.apdu.error_class_name == "Property"
    assert pkt.apdu.error_code == 32  # unknown-property


def test_reject_pdu():
    """APDU type 6 — Reject, invoke=5, reason=Unrecognized-Service (9)."""
    # 60 05 09
    pkt = parse_packet(make_raw("810A0009 0100 600509"))
    assert pkt.apdu.pdu_type == 6
    assert pkt.apdu.pdu_type_name == "Reject"
    assert pkt.apdu.invoke_id == 5
    assert pkt.apdu.reject_reason == 9
    assert pkt.apdu.reject_reason_name == "Unrecognized-Service"


def test_reject_buffer_overflow():
    """APDU type 6 — Reject, reason=Buffer-Overflow (1)."""
    # 60 0A 01
    pkt = parse_packet(make_raw("810A0009 0100 600A01"))
    assert pkt.apdu.reject_reason == 1
    assert pkt.apdu.reject_reason_name == "Buffer-Overflow"


def test_abort_pdu():
    """APDU type 7 — Abort, invoke=10, reason=Invalid-APDU-In-This-State (2)."""
    # 70 0A 02
    pkt = parse_packet(make_raw("810A0009 0100 700A02"))
    assert pkt.apdu.pdu_type == 7
    assert pkt.apdu.pdu_type_name == "Abort"
    assert pkt.apdu.invoke_id == 10
    assert pkt.apdu.abort_reason == 2
    assert pkt.apdu.abort_reason_name == "Invalid-APDU-In-This-State"


def test_abort_segmentation_not_supported():
    """APDU type 7 — Abort, reason=Segmentation-Not-Supported (4)."""
    # 70 03 04
    pkt = parse_packet(make_raw("810A0009 0100 700304"))
    assert pkt.apdu.abort_reason == 4
    assert pkt.apdu.abort_reason_name == "Segmentation-Not-Supported"


if _DIRECT_RUN:
    for fn in [
        test_unconfirmed_who_is, test_unconfirmed_iam, test_unconfirmed_who_has,
        test_unconfirmed_time_sync, test_unconfirmed_cov_notification,
        test_confirmed_readproperty, test_confirmed_writeproperty,
        test_confirmed_subscribe_cov, test_confirmed_cov_notification,
        test_confirmed_readproperty_multiple,
        test_simple_ack_writeproperty, test_simple_ack_subscribe_cov,
        test_complex_ack_readproperty, test_complex_ack_readproperty_multiple,
        test_segment_ack,
        test_error_pdu, test_error_pdu_property_class,
        test_reject_pdu, test_reject_buffer_overflow,
        test_abort_pdu, test_abort_segmentation_not_supported,
    ]:
        run_test(fn.__doc__.strip(), fn)


# ─── GROUP 4: Pipeline & Edge Cases ──────────────────────────────────────────

if _DIRECT_RUN: print("\n── Pipeline & Edge Cases ──")


def test_malformed_too_short():
    """Malformed — 1-byte packet, BVLC parse error, no crash."""
    pkt = parse_packet(make_raw("81"))
    assert pkt.parse_error is not None
    assert "BVLC" in pkt.parse_error
    assert pkt.bvlc is None


def test_malformed_bad_bvlc_type():
    """Malformed — wrong BVLC type 0x82, parse error at BVLC layer."""
    pkt = parse_packet(make_raw("820B000C 0100 1008"))
    assert pkt.parse_error is not None
    assert "BVLC" in pkt.parse_error
    assert pkt.bvlc is None


def test_malformed_bad_npdu_version():
    """Malformed — valid BVLC but NPDU version 0x02, parse error at NPDU layer."""
    pkt = parse_packet(make_raw("810A0008 0200 1008"))
    assert pkt.bvlc is not None  # BVLC parsed OK
    assert pkt.parse_error is not None
    assert "NPDU" in pkt.parse_error
    assert pkt.npdu is None


def test_malformed_truncated_apdu():
    """Malformed — valid BVLC+NPDU but APDU is empty."""
    pkt = parse_packet(make_raw("810A0006 0100"))
    assert pkt.bvlc is not None
    assert pkt.npdu is not None
    assert pkt.apdu is None
    # Empty remaining → no APDU, but no error (NPDU-only is handled)
    assert pkt.parse_error is None


def test_malformed_unknown_pdu_type():
    """Malformed — APDU PDU type 0xF0 (type 15), unknown."""
    pkt = parse_packet(make_raw("810A0007 0100 F0"))
    assert pkt.bvlc is not None
    assert pkt.npdu is not None
    assert pkt.parse_error is not None
    assert "APDU" in pkt.parse_error


def test_sequential_packet_ids():
    """Pipeline — packet IDs increment sequentially."""
    reset_packet_counter()
    pkt_a = parse_packet(make_raw("810A0008 0100 1008"))
    pkt_b = parse_packet(make_raw("810A0008 0100 1008"))
    pkt_c = parse_packet(make_raw("810A0008 0100 1008"))
    assert pkt_a.id == 1
    assert pkt_b.id == 2
    assert pkt_c.id == 3


def test_raw_hex_preserved():
    """Pipeline — raw_hex matches the original packet bytes."""
    raw = make_raw("810A0008 0100 1008")
    pkt = parse_packet(raw)
    assert pkt.raw_hex == "810a000801001008"


def test_effective_source_ip_default():
    """Pipeline — effective_source_ip defaults to transport source_ip."""
    pkt = parse_packet(make_raw("810A0008 0100 1008", src="10.0.0.5"))
    assert pkt.source_ip == "10.0.0.5"
    assert pkt.effective_source_ip == "10.0.0.5"


def test_summary_format():
    """Pipeline — summary string has expected structure."""
    reset_packet_counter()
    pkt = parse_packet(make_raw("810B0008 0100 1008", src="10.0.0.1", dst="10.0.0.255"))
    assert "10.0.0.1" in pkt.summary
    assert "10.0.0.255" in pkt.summary
    assert "Who-Is" in pkt.summary


if _DIRECT_RUN:
    for fn in [
        test_malformed_too_short, test_malformed_bad_bvlc_type,
        test_malformed_bad_npdu_version, test_malformed_truncated_apdu,
        test_malformed_unknown_pdu_type,
        test_sequential_packet_ids, test_raw_hex_preserved,
        test_effective_source_ip_default, test_summary_format,
    ]:
        run_test(fn.__doc__.strip(), fn)


# ─── GROUP 5: Direct Layer Parser Unit Tests ─────────────────────────────────

if _DIRECT_RUN: print("\n── Direct Layer Parsers ──")


def test_bvlc_parser_directly():
    """BVLC parser — returns remaining bytes correctly."""
    data = bytes.fromhex("810B000C 0120FFFF00FF 1008".replace(" ", ""))
    msg, remaining = parse_bvlc(data)
    assert msg.type == 0x81
    assert msg.function == 0x0B
    assert msg.length == 12
    assert remaining == bytes.fromhex("0120FFFF00FF1008")


def test_bvlc_forwarded_parser():
    """BVLC parser — Forwarded-NPDU extracts 6-byte originating addr."""
    data = bytes.fromhex("8104000E C0A80114BAC0 0100 1008".replace(" ", ""))
    msg, remaining = parse_bvlc(data)
    assert msg.originating_ip == "192.168.1.20"
    assert msg.originating_port == 47808
    assert remaining == bytes.fromhex("01001008")


def test_npdu_parser_directly():
    """NPDU parser — parses DNET+SNET and returns APDU bytes."""
    data = bytes.fromhex("0128 000A 01 05 0014 01 0A FE 1008".replace(" ", ""))
    msg, remaining = parse_npdu(data)
    assert msg.destination_network == 10
    assert msg.destination_address == "05"
    assert msg.source_network == 20
    assert msg.source_address == "0a"
    assert msg.hop_count == 254
    assert remaining == bytes.fromhex("1008")


def test_apdu_parser_directly():
    """APDU parser — parses confirmed request header fields."""
    data = bytes.fromhex("0004050C 0C00000001 1955".replace(" ", ""))
    msg = parse_apdu(data)
    assert msg.pdu_type == 0
    assert msg.service_choice == 12  # ReadProperty
    assert msg.invoke_id == 5
    assert msg.segmented is False
    assert msg.object_identifier.instance == 1


def test_bvlc_parser_raises_on_short():
    """BVLC parser — raises ValueError on short input."""
    try:
        parse_bvlc(bytes.fromhex("81"))
        assert False, "Should have raised"
    except ValueError as e:
        assert "too short" in str(e)


def test_npdu_parser_raises_on_bad_version():
    """NPDU parser — raises ValueError on wrong version."""
    try:
        parse_npdu(bytes.fromhex("0200"))
        assert False, "Should have raised"
    except ValueError as e:
        assert "version" in str(e).lower()


def test_apdu_parser_raises_on_unknown_type():
    """APDU parser — raises ValueError on unknown PDU type 15."""
    try:
        parse_apdu(bytes.fromhex("F0"))
        assert False, "Should have raised"
    except ValueError as e:
        assert "Unknown" in str(e)


if _DIRECT_RUN:
    for fn in [
        test_bvlc_parser_directly, test_bvlc_forwarded_parser,
        test_npdu_parser_directly, test_apdu_parser_directly,
        test_bvlc_parser_raises_on_short, test_npdu_parser_raises_on_bad_version,
        test_apdu_parser_raises_on_unknown_type,
    ]:
        run_test(fn.__doc__.strip(), fn)

    # Summary
    total = passed + failed
    print(f"\n{'='*60}")
    print(f"  {passed}/{total} tests passed", end="")
    if failed:
        print(f"  ({failed} FAILED)")
    else:
        print("  — all clear!")
    print(f"{'='*60}")
    exit(0 if failed == 0 else 1)
