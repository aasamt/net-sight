"""Phase 4 analysis engine tests — device registry, traffic stats, anomaly detector, packet inspector.

Uses hand-crafted ParsedPacket objects to exercise all analysis modules
without requiring actual packet capture or parsing.
"""

import time
from backend.models.bvlc import BVLCMessage
from backend.models.npdu import NPDUMessage
from backend.models.apdu import APDUMessage, ObjectIdentifier
from backend.models.packet import ParsedPacket
from backend.analysis.device_registry import DeviceRegistry
from backend.analysis.traffic_stats import TrafficStats
from backend.analysis.anomaly_detector import AnomalyDetector, AnomalyType
from backend.analysis.packet_inspector import (
    inspect_packet,
    inspect_packet_dict,
    DetailLevel,
)

passed = 0
failed = 0


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


# ─── Helpers ──────────────────────────────────────────────────────────────────

_pkt_id = 0


def make_packet(
    *,
    src_ip: str = "192.168.1.10",
    dst_ip: str = "192.168.1.20",
    length: int = 100,
    ts: float | None = None,
    bvlc_function: int = 0x0A,
    bvlc_function_name: str = "Original-Unicast-NPDU",
    bvlc_result_code: int | None = None,
    bvlc_result_name: str | None = None,
    npdu_priority: int = 0,
    npdu_priority_name: str = "Normal",
    npdu_is_network_msg: bool = False,
    npdu_net_msg_type: int | None = None,
    npdu_net_msg_name: str | None = None,
    npdu_reject_reason: int | None = None,
    npdu_reject_reason_name: str | None = None,
    apdu_pdu_type: int = 1,
    apdu_service_choice: int = 8,
    apdu_service_name: str = "Who-Is",
    apdu_is_confirmed: bool = False,
    apdu_invoke_id: int | None = None,
    obj_type: int | None = None,
    obj_type_name: str | None = None,
    obj_instance: int | None = None,
    apdu_error_class: int | None = None,
    apdu_error_class_name: str | None = None,
    apdu_error_code: int | None = None,
    apdu_reject_reason: int | None = None,
    apdu_reject_reason_name: str | None = None,
    apdu_abort_reason: int | None = None,
    apdu_abort_reason_name: str | None = None,
    skip_bvlc: bool = False,
    skip_npdu: bool = False,
    skip_apdu: bool = False,
    parse_error: str | None = None,
) -> ParsedPacket:
    """Build a ParsedPacket with minimal boilerplate."""
    global _pkt_id
    _pkt_id += 1

    obj_id = None
    if obj_type is not None and obj_instance is not None:
        obj_id = ObjectIdentifier(
            object_type=obj_type,
            object_type_name=obj_type_name or f"Type-{obj_type}",
            instance=obj_instance,
        )

    bvlc = None if skip_bvlc else BVLCMessage(
        type=0x81,
        function=bvlc_function,
        function_name=bvlc_function_name,
        length=length,
        result_code=bvlc_result_code,
        result_name=bvlc_result_name,
    )

    npdu = None if skip_npdu else NPDUMessage(
        version=1,
        is_network_message=npdu_is_network_msg,
        expecting_reply=False,
        priority=npdu_priority,
        priority_name=npdu_priority_name,
        network_message_type=npdu_net_msg_type,
        network_message_name=npdu_net_msg_name,
        reject_reason=npdu_reject_reason,
        reject_reason_name=npdu_reject_reason_name,
    )

    apdu = None if skip_apdu else APDUMessage(
        pdu_type=apdu_pdu_type,
        pdu_type_name={
            0: "Confirmed-Request", 1: "Unconfirmed-Request",
            2: "Simple-ACK", 3: "Complex-ACK", 4: "Segment-ACK",
            5: "Error", 6: "Reject", 7: "Abort",
        }.get(apdu_pdu_type, f"Type-{apdu_pdu_type}"),
        service_choice=apdu_service_choice,
        service_name=apdu_service_name,
        is_confirmed=apdu_is_confirmed,
        invoke_id=apdu_invoke_id,
        object_identifier=obj_id,
        error_class=apdu_error_class,
        error_class_name=apdu_error_class_name,
        error_code=apdu_error_code,
        reject_reason=apdu_reject_reason,
        reject_reason_name=apdu_reject_reason_name,
        abort_reason=apdu_abort_reason,
        abort_reason_name=apdu_abort_reason_name,
    )

    return ParsedPacket(
        id=_pkt_id,
        timestamp=ts or time.time(),
        length=length,
        source_ip=src_ip,
        source_port=47808,
        destination_ip=dst_ip,
        destination_port=47808,
        effective_source_ip=src_ip,
        effective_source_port=47808,
        raw_hex="00" * length,
        bvlc=bvlc,
        npdu=npdu,
        apdu=apdu,
        parse_error=parse_error,
    )


def make_iam(
    instance: int, ip: str = "192.168.1.20", ts: float | None = None
) -> ParsedPacket:
    """Build an I-Am packet."""
    return make_packet(
        src_ip=ip,
        dst_ip="192.168.1.255",
        bvlc_function=0x0B,
        bvlc_function_name="Original-Broadcast-NPDU",
        apdu_pdu_type=1,
        apdu_service_choice=0,
        apdu_service_name="I-Am",
        obj_type=8,
        obj_type_name="Device",
        obj_instance=instance,
        ts=ts,
    )


# Guard: only run the custom test runner when executed directly, not via pytest
_DIRECT_RUN = __name__ == "__main__"

# ─── GROUP 1: Device Registry ────────────────────────────────────────────────

if _DIRECT_RUN: print("\n── Device Registry ──")


def test_registry_iam_registers_device():
    """Registry — I-Am registers a new device."""
    reg = DeviceRegistry()
    pkt = make_iam(100, "192.168.1.20")
    reg.process_packet(pkt)
    assert reg.get_device_count() == 1
    dev = reg.get_device(100)
    assert dev is not None
    assert dev.instance == 100
    assert dev.ip == "192.168.1.20"


def test_registry_multiple_devices():
    """Registry — multiple I-Am packets register distinct devices."""
    reg = DeviceRegistry()
    reg.process_packet(make_iam(100, "192.168.1.20"))
    reg.process_packet(make_iam(200, "192.168.1.30"))
    reg.process_packet(make_iam(300, "192.168.1.40"))
    assert reg.get_device_count() == 3
    devs = reg.get_all_devices()
    instances = {d.instance for d in devs}
    assert instances == {100, 200, 300}


def test_registry_duplicate_iam_updates():
    """Registry — duplicate I-Am updates last_seen, not device count."""
    reg = DeviceRegistry()
    t1 = 1000.0
    t2 = 2000.0
    reg.process_packet(make_iam(100, "192.168.1.20", ts=t1))
    reg.process_packet(make_iam(100, "192.168.1.20", ts=t2))
    assert reg.get_device_count() == 1
    dev = reg.get_device(100)
    assert dev.first_seen == t1
    assert dev.last_seen == t2


def test_registry_ip_to_device():
    """Registry — IP-to-device lookup after I-Am."""
    reg = DeviceRegistry()
    reg.process_packet(make_iam(100, "192.168.1.20"))
    dev = reg.get_device_by_ip("192.168.1.20")
    assert dev is not None
    assert dev.instance == 100
    assert reg.get_device_by_ip("10.0.0.1") is None


def test_registry_traffic_attribution():
    """Registry — non-I-Am packets attributed to known device by IP."""
    reg = DeviceRegistry()
    reg.process_packet(make_iam(100, "192.168.1.20"))
    # Send a ReadProperty from the same IP
    rp = make_packet(
        src_ip="192.168.1.20",
        apdu_pdu_type=0,
        apdu_service_choice=12,
        apdu_service_name="ReadProperty",
        apdu_is_confirmed=True,
        apdu_invoke_id=5,
        length=80,
    )
    reg.process_packet(rp)
    dev = reg.get_device(100)
    assert dev.packet_count == 2  # I-Am + ReadProperty
    assert dev.byte_count > 0


def test_registry_unknown_ip_no_crash():
    """Registry — packets from unknown IP are silently ignored."""
    reg = DeviceRegistry()
    pkt = make_packet(src_ip="10.0.0.99")
    reg.process_packet(pkt)  # Should not crash
    assert reg.get_device_count() == 0


def test_registry_reset():
    """Registry — reset clears all state."""
    reg = DeviceRegistry()
    reg.process_packet(make_iam(100, "192.168.1.20"))
    assert reg.get_device_count() == 1
    reg.reset()
    assert reg.get_device_count() == 0


def test_registry_to_dict():
    """Registry — serialization produces expected fields."""
    reg = DeviceRegistry()
    reg.process_packet(make_iam(100, "192.168.1.20"))
    dicts = reg.to_dict_list()
    assert len(dicts) == 1
    d = dicts[0]
    assert d["instance"] == 100
    assert d["ip"] == "192.168.1.20"
    assert "first_seen" in d
    assert "packet_count" in d


if _DIRECT_RUN:
    for fn in [
        test_registry_iam_registers_device,
        test_registry_multiple_devices,
        test_registry_duplicate_iam_updates,
        test_registry_ip_to_device,
        test_registry_traffic_attribution,
        test_registry_unknown_ip_no_crash,
        test_registry_reset,
        test_registry_to_dict,
    ]:
        run_test(fn.__doc__.strip(), fn)


# ─── GROUP 2: Traffic Stats ──────────────────────────────────────────────────

if _DIRECT_RUN: print("\n── Traffic Stats ──")


def test_stats_global_counters():
    """Stats — global packet and byte counts."""
    stats = TrafficStats()
    stats.process_packet(make_packet(length=100))
    stats.process_packet(make_packet(length=200))
    stats.process_packet(make_packet(length=50))
    assert stats.total_packets == 3
    assert stats.total_bytes == 350


def test_stats_summary():
    """Stats — summary dict has expected keys."""
    stats = TrafficStats()
    t = 1000.0
    stats.process_packet(make_packet(length=100, ts=t))
    stats.process_packet(make_packet(length=200, ts=t + 5))
    summary = stats.get_summary()
    assert summary["total_packets"] == 2
    assert summary["total_bytes"] == 300
    assert summary["duration_seconds"] == 5.0
    assert "confirmed_count" in summary
    assert "error_count" in summary


def test_stats_confirmed_vs_unconfirmed():
    """Stats — confirmed vs unconfirmed ratio tracking."""
    stats = TrafficStats()
    # 2 confirmed requests
    stats.process_packet(make_packet(apdu_pdu_type=0, apdu_is_confirmed=True))
    stats.process_packet(make_packet(apdu_pdu_type=0, apdu_is_confirmed=True))
    # 3 unconfirmed requests
    stats.process_packet(make_packet(apdu_pdu_type=1))
    stats.process_packet(make_packet(apdu_pdu_type=1))
    stats.process_packet(make_packet(apdu_pdu_type=1))
    summary = stats.get_summary()
    assert summary["confirmed_count"] == 2
    assert summary["unconfirmed_count"] == 3
    assert abs(summary["confirmed_ratio"] - 0.4) < 0.01


def test_stats_error_reject_abort():
    """Stats — error/reject/abort counters."""
    stats = TrafficStats()
    stats.process_packet(make_packet(apdu_pdu_type=5, apdu_service_name="Error"))
    stats.process_packet(make_packet(apdu_pdu_type=5, apdu_service_name="Error"))
    stats.process_packet(make_packet(apdu_pdu_type=6, apdu_service_name="Reject"))
    stats.process_packet(make_packet(apdu_pdu_type=7, apdu_service_name="Abort"))
    summary = stats.get_summary()
    assert summary["error_count"] == 2
    assert summary["reject_count"] == 1
    assert summary["abort_count"] == 1


def test_stats_top_talkers():
    """Stats — top talkers ranked by packet count."""
    stats = TrafficStats()
    for _ in range(10):
        stats.process_packet(make_packet(src_ip="192.168.1.10"))
    for _ in range(5):
        stats.process_packet(make_packet(src_ip="192.168.1.20"))
    for _ in range(20):
        stats.process_packet(make_packet(src_ip="192.168.1.30"))
    talkers = stats.get_top_talkers(n=3)
    assert len(talkers) == 3
    assert talkers[0]["ip"] == "192.168.1.30"
    assert talkers[0]["packet_count"] == 20
    assert talkers[1]["ip"] == "192.168.1.10"


def test_stats_service_breakdown():
    """Stats — per-service breakdown."""
    stats = TrafficStats()
    stats.process_packet(make_packet(apdu_service_name="Who-Is"))
    stats.process_packet(make_packet(apdu_service_name="Who-Is"))
    stats.process_packet(make_packet(apdu_service_name="ReadProperty"))
    breakdown = stats.get_service_breakdown()
    assert len(breakdown) == 2
    assert breakdown[0]["name"] == "Who-Is"
    assert breakdown[0]["packet_count"] == 2


def test_stats_bvlc_breakdown():
    """Stats — per-BVLC-function breakdown."""
    stats = TrafficStats()
    stats.process_packet(make_packet(bvlc_function_name="Original-Unicast-NPDU"))
    stats.process_packet(make_packet(bvlc_function_name="Original-Broadcast-NPDU"))
    stats.process_packet(make_packet(bvlc_function_name="Original-Broadcast-NPDU"))
    breakdown = stats.get_bvlc_breakdown()
    assert len(breakdown) == 2
    assert breakdown[0]["name"] == "Original-Broadcast-NPDU"


def test_stats_priority_breakdown():
    """Stats — per-priority breakdown."""
    stats = TrafficStats()
    stats.process_packet(make_packet(npdu_priority=0, npdu_priority_name="Normal"))
    stats.process_packet(make_packet(npdu_priority=3, npdu_priority_name="Life-Safety"))
    stats.process_packet(make_packet(npdu_priority=0, npdu_priority_name="Normal"))
    breakdown = stats.get_priority_breakdown()
    assert len(breakdown) == 2
    assert breakdown[0]["name"] == "Normal"
    assert breakdown[0]["packet_count"] == 2


def test_stats_rates():
    """Stats — rate calculation returns expected structure."""
    stats = TrafficStats()
    now = time.time()
    for i in range(5):
        stats.process_packet(make_packet(ts=now + i * 0.1))
    rates = stats.get_rates()
    assert "1s" in rates
    assert "10s" in rates
    assert "60s" in rates
    assert "pps" in rates["1s"]
    assert "bps" in rates["1s"]


def test_stats_reset():
    """Stats — reset clears all state."""
    stats = TrafficStats()
    stats.process_packet(make_packet(length=100))
    stats.process_packet(make_packet(length=200))
    stats.reset()
    assert stats.total_packets == 0
    assert stats.total_bytes == 0
    summary = stats.get_summary()
    assert summary["total_packets"] == 0


if _DIRECT_RUN:
    for fn in [
        test_stats_global_counters,
        test_stats_summary,
        test_stats_confirmed_vs_unconfirmed,
        test_stats_error_reject_abort,
        test_stats_top_talkers,
        test_stats_service_breakdown,
        test_stats_bvlc_breakdown,
        test_stats_priority_breakdown,
        test_stats_rates,
        test_stats_reset,
    ]:
        run_test(fn.__doc__.strip(), fn)


# ─── GROUP 3: Anomaly Detector ───────────────────────────────────────────────

if _DIRECT_RUN: print("\n── Anomaly Detector ──")


def test_anomaly_chatty_device():
    """Anomaly — chatty device detected when pps exceeds threshold."""
    detector = AnomalyDetector(chatty_pps=5, window_seconds=1.0, cooldown_seconds=0)
    now = 1000.0
    new_anomalies = []
    for i in range(10):
        result = detector.process_packet(
            make_packet(src_ip="192.168.1.10", ts=now + i * 0.05)
        )
        new_anomalies.extend(result)
    assert any(a.type == AnomalyType.CHATTY_DEVICE for a in new_anomalies)
    chatty = [a for a in new_anomalies if a.type == AnomalyType.CHATTY_DEVICE]
    assert chatty[0].source_ip == "192.168.1.10"


def test_anomaly_broadcast_storm():
    """Anomaly — broadcast storm detected on Who-Is/I-Am flood."""
    detector = AnomalyDetector(broadcast_pps=5, window_seconds=1.0, cooldown_seconds=0)
    now = 2000.0
    new_anomalies = []
    for i in range(10):
        pkt = make_packet(
            src_ip=f"192.168.1.{i + 10}",
            apdu_pdu_type=1,
            apdu_service_choice=8,
            apdu_service_name="Who-Is",
            ts=now + i * 0.05,
        )
        result = detector.process_packet(pkt)
        new_anomalies.extend(result)
    assert any(a.type == AnomalyType.BROADCAST_STORM for a in new_anomalies)
    storm = [a for a in new_anomalies if a.type == AnomalyType.BROADCAST_STORM][0]
    assert storm.details["storm_type"] == "discovery"


def test_anomaly_broadcast_storm_who_has():
    """Anomaly — Who-Has/I-Have flood triggers discovery broadcast storm."""
    detector = AnomalyDetector(broadcast_pps=5, window_seconds=1.0, cooldown_seconds=0)
    now = 2050.0
    new_anomalies = []
    for i in range(10):
        # Alternate Who-Has (7) and I-Have (1)
        svc = 7 if i % 2 == 0 else 1
        svc_name = "Who-Has" if svc == 7 else "I-Have"
        pkt = make_packet(
            src_ip=f"192.168.1.{i + 10}",
            apdu_pdu_type=1,
            apdu_service_choice=svc,
            apdu_service_name=svc_name,
            ts=now + i * 0.05,
        )
        result = detector.process_packet(pkt)
        new_anomalies.extend(result)
    storm = [a for a in new_anomalies if a.type == AnomalyType.BROADCAST_STORM]
    assert len(storm) >= 1
    assert storm[0].details["storm_type"] == "discovery"
    assert "discovery flood" in storm[0].message


def test_anomaly_broadcast_storm_timesync():
    """Anomaly — TimeSynchronization flood triggers timesync broadcast storm."""
    detector = AnomalyDetector(
        timesync_pps=5, broadcast_pps=100, window_seconds=1.0, cooldown_seconds=0,
    )
    now = 2100.0
    new_anomalies = []
    for i in range(10):
        pkt = make_packet(
            src_ip="192.168.1.80",
            apdu_pdu_type=1,
            apdu_service_choice=6,
            apdu_service_name="TimeSynchronization",
            ts=now + i * 0.05,
        )
        result = detector.process_packet(pkt)
        new_anomalies.extend(result)
    storm = [a for a in new_anomalies if a.type == AnomalyType.BROADCAST_STORM]
    assert len(storm) >= 1
    assert storm[0].details["storm_type"] == "timesync"
    assert "time sync flood" in storm[0].message


def test_anomaly_broadcast_storm_unconfirmed():
    """Anomaly — COV notification flood triggers unconfirmed broadcast storm."""
    detector = AnomalyDetector(
        unconfirmed_flood_pps=5, broadcast_pps=100, window_seconds=1.0, cooldown_seconds=0,
    )
    now = 2150.0
    new_anomalies = []
    for i in range(10):
        pkt = make_packet(
            src_ip="192.168.1.50",
            apdu_pdu_type=1,
            apdu_service_choice=2,
            apdu_service_name="UnconfirmedCOVNotification",
            ts=now + i * 0.05,
        )
        result = detector.process_packet(pkt)
        new_anomalies.extend(result)
    storm = [a for a in new_anomalies if a.type == AnomalyType.BROADCAST_STORM]
    assert len(storm) >= 1
    assert storm[0].details["storm_type"] == "unconfirmed"
    assert "COV/WriteGroup" in storm[0].message


def test_anomaly_broadcast_storm_router_discovery():
    """Anomaly — Who-Is-Router flood (NPDU network msg, no APDU) triggers router storm."""
    detector = AnomalyDetector(
        router_discovery_pps=5, broadcast_pps=100, window_seconds=1.0, cooldown_seconds=0,
    )
    now = 2200.0
    new_anomalies = []
    for i in range(10):
        pkt = make_packet(
            src_ip="192.168.1.90",
            npdu_is_network_msg=True,
            npdu_net_msg_type=0x00,
            npdu_net_msg_name="Who-Is-Router-To-Network",
            skip_apdu=True,
            ts=now + i * 0.05,
        )
        result = detector.process_packet(pkt)
        new_anomalies.extend(result)
    storm = [a for a in new_anomalies if a.type == AnomalyType.BROADCAST_STORM]
    assert len(storm) >= 1
    assert storm[0].details["storm_type"] == "router"
    assert "router discovery flood" in storm[0].message


def test_anomaly_broadcast_storm_aggregate():
    """Anomaly — mixed broadcast traffic below sub-type thresholds but above aggregate."""
    detector = AnomalyDetector(
        broadcast_pps=5,
        timesync_pps=100,
        router_discovery_pps=100,
        window_seconds=1.0,
        cooldown_seconds=0,
    )
    now = 2250.0
    new_anomalies = []
    # Send 4 Who-Is + 4 TimeSynchronization — each sub-type is 4 pps (< their thresholds)
    # but aggregate is 8 pps (> broadcast_pps=5)
    for i in range(4):
        pkt = make_packet(
            src_ip=f"192.168.1.{i + 10}",
            apdu_pdu_type=1,
            apdu_service_choice=8,
            apdu_service_name="Who-Is",
            ts=now + i * 0.05,
        )
        result = detector.process_packet(pkt)
        new_anomalies.extend(result)
    for i in range(4):
        pkt = make_packet(
            src_ip="192.168.1.80",
            apdu_pdu_type=1,
            apdu_service_choice=6,
            apdu_service_name="TimeSynchronization",
            ts=now + 0.2 + i * 0.05,
        )
        result = detector.process_packet(pkt)
        new_anomalies.extend(result)
    storm = [a for a in new_anomalies if a.type == AnomalyType.BROADCAST_STORM]
    assert len(storm) >= 1
    # Could be discovery (if it fires first) or aggregate — both are valid
    types_seen = {s.details["storm_type"] for s in storm}
    assert "discovery" in types_seen or "aggregate" in types_seen


def test_anomaly_broadcast_storm_below_threshold():
    """Anomaly — sub-threshold broadcast traffic does NOT trigger storm."""
    detector = AnomalyDetector(
        broadcast_pps=50, timesync_pps=50, router_discovery_pps=50,
        window_seconds=1.0, cooldown_seconds=0,
    )
    now = 2300.0
    # Send 3 Who-Is at 1 pps — well below any threshold
    for i in range(3):
        pkt = make_packet(
            src_ip="192.168.1.10",
            apdu_pdu_type=1,
            apdu_service_choice=8,
            apdu_service_name="Who-Is",
            ts=now + i * 1.0,
        )
        result = detector.process_packet(pkt)
        storm = [a for a in result if a.type == AnomalyType.BROADCAST_STORM]
        assert len(storm) == 0


def test_anomaly_broadcast_storm_global_broadcast():
    """Anomaly — global broadcast (DNET=0xFFFF) noted in storm details."""
    detector = AnomalyDetector(broadcast_pps=5, window_seconds=1.0, cooldown_seconds=0)
    now = 2350.0
    new_anomalies = []
    for i in range(10):
        pkt = make_packet(
            src_ip=f"192.168.1.{i + 10}",
            apdu_pdu_type=1,
            apdu_service_choice=8,
            apdu_service_name="Who-Is",
            ts=now + i * 0.05,
        )
        # Set NPDU destination_network to 0xFFFF (global broadcast)
        pkt.npdu.destination_network = 0xFFFF
        result = detector.process_packet(pkt)
        new_anomalies.extend(result)
    storm = [a for a in new_anomalies if a.type == AnomalyType.BROADCAST_STORM]
    assert len(storm) >= 1
    assert storm[0].details["global_broadcast"] is True


def test_anomaly_high_error_rate():
    """Anomaly — high error rate detected."""
    detector = AnomalyDetector(error_pps=3, window_seconds=1.0, cooldown_seconds=0)
    now = 3000.0
    new_anomalies = []
    for i in range(5):
        pkt = make_packet(
            apdu_pdu_type=5,
            apdu_service_name="Error",
            ts=now + i * 0.1,
        )
        result = detector.process_packet(pkt)
        new_anomalies.extend(result)
    assert any(a.type == AnomalyType.HIGH_ERROR_RATE for a in new_anomalies)


def test_anomaly_high_reject_rate():
    """Anomaly — high reject rate detected."""
    detector = AnomalyDetector(reject_pps=3, window_seconds=1.0, cooldown_seconds=0)
    now = 4000.0
    new_anomalies = []
    for i in range(5):
        pkt = make_packet(apdu_pdu_type=6, ts=now + i * 0.1)
        result = detector.process_packet(pkt)
        new_anomalies.extend(result)
    assert any(a.type == AnomalyType.HIGH_REJECT_RATE for a in new_anomalies)


def test_anomaly_high_abort_rate():
    """Anomaly — high abort rate detected."""
    detector = AnomalyDetector(abort_pps=3, window_seconds=1.0, cooldown_seconds=0)
    now = 5000.0
    new_anomalies = []
    for i in range(5):
        pkt = make_packet(apdu_pdu_type=7, ts=now + i * 0.1)
        result = detector.process_packet(pkt)
        new_anomalies.extend(result)
    assert any(a.type == AnomalyType.HIGH_ABORT_RATE for a in new_anomalies)


def test_anomaly_routing_issue():
    """Anomaly — routing issue on Reject-Message-To-Network."""
    detector = AnomalyDetector(cooldown_seconds=0)
    pkt = make_packet(
        npdu_is_network_msg=True,
        npdu_net_msg_type=0x03,
        npdu_net_msg_name="Reject-Message-To-Network",
        npdu_reject_reason=1,
        npdu_reject_reason_name="No-Route",
        skip_apdu=True,
    )
    result = detector.process_packet(pkt)
    assert len(result) >= 1
    routing = [a for a in result if a.type == AnomalyType.ROUTING_ISSUE]
    assert len(routing) == 1
    assert "No-Route" in routing[0].message


def test_anomaly_foreign_device_nak():
    """Anomaly — BVLC-Result NAK detected."""
    detector = AnomalyDetector(cooldown_seconds=0)
    pkt = make_packet(
        bvlc_function=0x00,
        bvlc_function_name="BVLC-Result",
        bvlc_result_code=0x0050,
        bvlc_result_name="Register-Foreign-Device-NAK",
        skip_npdu=True,
        skip_apdu=True,
    )
    result = detector.process_packet(pkt)
    nak = [a for a in result if a.type == AnomalyType.FOREIGN_DEVICE_NAK]
    assert len(nak) == 1
    assert "Register-Foreign-Device-NAK" in nak[0].message


def test_anomaly_duplicate_device_id():
    """Anomaly — duplicate device ID detected when same instance from different IPs."""
    detector = AnomalyDetector(cooldown_seconds=0)
    now = 5500.0
    # First I-Am from 192.168.1.20 with instance 200
    pkt1 = make_iam(200, "192.168.1.20", ts=now)
    result1 = detector.process_packet(pkt1)
    # No anomaly yet — first time seeing this instance
    dup1 = [a for a in result1 if a.type == AnomalyType.DUPLICATE_DEVICE_ID]
    assert len(dup1) == 0

    # Second I-Am from 192.168.1.30 with SAME instance 200
    pkt2 = make_iam(200, "192.168.1.30", ts=now + 0.1)
    result2 = detector.process_packet(pkt2)
    dup2 = [a for a in result2 if a.type == AnomalyType.DUPLICATE_DEVICE_ID]
    assert len(dup2) == 1
    assert dup2[0].severity == "critical"
    assert "200" in dup2[0].message
    assert "192.168.1.20" in dup2[0].message
    assert "192.168.1.30" in dup2[0].message
    assert dup2[0].details["device_instance"] == 200
    assert set(dup2[0].details["ips"]) == {"192.168.1.20", "192.168.1.30"}


def test_anomaly_duplicate_device_id_non_iam():
    """Anomaly — duplicate device ID detected from non-I-Am traffic (e.g. ReadProperty)."""
    detector = AnomalyDetector(cooldown_seconds=0)
    now = 5550.0
    # I-Am establishes Device:200 at 192.168.1.20
    pkt1 = make_iam(200, "192.168.1.20", ts=now)
    result1 = detector.process_packet(pkt1)
    assert not [a for a in result1 if a.type == AnomalyType.DUPLICATE_DEVICE_ID]

    # ReadProperty from a DIFFERENT IP referencing Device:200
    pkt2 = make_packet(
        src_ip="192.168.1.30",
        apdu_pdu_type=0,
        apdu_service_choice=12,
        apdu_service_name="ReadProperty",
        apdu_is_confirmed=True,
        apdu_invoke_id=1,
        obj_type=8,
        obj_type_name="Device",
        obj_instance=200,
        ts=now + 0.1,
    )
    result2 = detector.process_packet(pkt2)
    dup = [a for a in result2 if a.type == AnomalyType.DUPLICATE_DEVICE_ID]
    assert len(dup) == 1
    assert "200" in dup[0].message
    assert set(dup[0].details["ips"]) == {"192.168.1.20", "192.168.1.30"}


def test_anomaly_duplicate_non_device_object_ignored():
    """Anomaly — duplicate instance on non-Device objects does not trigger."""
    detector = AnomalyDetector(cooldown_seconds=0)
    now = 5570.0
    # AnalogInput:1 from two different IPs should NOT trigger duplicate device ID
    pkt1 = make_packet(
        src_ip="192.168.1.20",
        obj_type=0, obj_type_name="Analog-Input", obj_instance=1,
        ts=now,
    )
    pkt2 = make_packet(
        src_ip="192.168.1.30",
        obj_type=0, obj_type_name="Analog-Input", obj_instance=1,
        ts=now + 0.1,
    )
    result1 = detector.process_packet(pkt1)
    result2 = detector.process_packet(pkt2)
    all_dup = [a for a in result1 + result2 if a.type == AnomalyType.DUPLICATE_DEVICE_ID]
    assert len(all_dup) == 0


def test_anomaly_no_duplicate_same_ip():
    """Anomaly — same instance from same IP is not a duplicate."""
    detector = AnomalyDetector(cooldown_seconds=0)
    now = 5600.0
    pkt1 = make_iam(300, "192.168.1.40", ts=now)
    pkt2 = make_iam(300, "192.168.1.40", ts=now + 1.0)
    result1 = detector.process_packet(pkt1)
    result2 = detector.process_packet(pkt2)
    all_dup = [a for a in result1 + result2 if a.type == AnomalyType.DUPLICATE_DEVICE_ID]
    assert len(all_dup) == 0


def test_anomaly_cooldown():
    """Anomaly — cooldown prevents duplicate alerts within window."""
    detector = AnomalyDetector(cooldown_seconds=60, chatty_pps=2, window_seconds=1.0)
    now = 6000.0
    all_anomalies = []
    for i in range(20):
        result = detector.process_packet(
            make_packet(src_ip="192.168.1.10", ts=now + i * 0.05)
        )
        all_anomalies.extend(result)
    chatty = [a for a in all_anomalies if a.type == AnomalyType.CHATTY_DEVICE]
    # Should only alert once due to 60s cooldown
    assert len(chatty) == 1


def test_anomaly_no_false_positive():
    """Anomaly — normal traffic produces no anomalies."""
    detector = AnomalyDetector()
    now = 7000.0
    for i in range(5):
        result = detector.process_packet(
            make_packet(src_ip="192.168.1.10", ts=now + i * 1.0)
        )
        assert len(result) == 0


def test_anomaly_reset():
    """Anomaly — reset clears all state."""
    detector = AnomalyDetector(chatty_pps=2, window_seconds=1.0, cooldown_seconds=0)
    now = 8000.0
    for i in range(10):
        detector.process_packet(make_packet(src_ip="192.168.1.10", ts=now + i * 0.05))
    assert detector.get_anomaly_count() > 0
    detector.reset()
    assert detector.get_anomaly_count() == 0


def test_anomaly_serialization():
    """Anomaly — to_dict_list produces expected format."""
    detector = AnomalyDetector(cooldown_seconds=0)
    pkt = make_packet(
        npdu_is_network_msg=True,
        npdu_net_msg_type=0x03,
        npdu_net_msg_name="Reject-Message-To-Network",
        npdu_reject_reason=1,
        npdu_reject_reason_name="No-Route",
        skip_apdu=True,
    )
    detector.process_packet(pkt)
    dicts = detector.to_dict_list()
    assert len(dicts) >= 1
    d = dicts[-1]
    assert d["type"] == "routing-issue"
    assert "timestamp" in d
    assert "details" in d


if _DIRECT_RUN:
    for fn in [
        test_anomaly_chatty_device,
        test_anomaly_broadcast_storm,
        test_anomaly_broadcast_storm_who_has,
        test_anomaly_broadcast_storm_timesync,
        test_anomaly_broadcast_storm_unconfirmed,
        test_anomaly_broadcast_storm_router_discovery,
        test_anomaly_broadcast_storm_aggregate,
        test_anomaly_broadcast_storm_below_threshold,
        test_anomaly_broadcast_storm_global_broadcast,
        test_anomaly_high_error_rate,
        test_anomaly_high_reject_rate,
        test_anomaly_high_abort_rate,
        test_anomaly_routing_issue,
        test_anomaly_foreign_device_nak,
        test_anomaly_duplicate_device_id,
        test_anomaly_duplicate_device_id_non_iam,
        test_anomaly_duplicate_non_device_object_ignored,
        test_anomaly_no_duplicate_same_ip,
        test_anomaly_cooldown,
        test_anomaly_no_false_positive,
        test_anomaly_reset,
        test_anomaly_serialization,
    ]:
        run_test(fn.__doc__.strip(), fn)


# ─── GROUP 4: Packet Inspector ───────────────────────────────────────────────

if _DIRECT_RUN: print("\n── Packet Inspector ──")


def test_inspector_summary():
    """Inspector — summary returns one-line string."""
    pkt = make_packet(src_ip="10.0.0.1", apdu_service_name="ReadProperty")
    result = inspect_packet(pkt, DetailLevel.SUMMARY)
    assert "10.0.0.1" in result
    assert "ReadProperty" in result
    assert "\n" not in result


def test_inspector_normal():
    """Inspector — normal returns multi-line with all layers."""
    pkt = make_packet(
        src_ip="10.0.0.1",
        apdu_service_name="ReadProperty",
        apdu_invoke_id=5,
        obj_type=0, obj_type_name="Analog-Input", obj_instance=1,
    )
    result = inspect_packet(pkt, DetailLevel.NORMAL)
    assert "BVLC:" in result
    assert "NPDU:" in result
    assert "APDU:" in result
    assert "ReadProperty" in result
    assert "Analog-Input:1" in result
    assert "invoke=5" in result


def test_inspector_full():
    """Inspector — full includes raw hex and separator lines."""
    pkt = make_packet(src_ip="10.0.0.1", apdu_service_name="I-Am", length=50)
    result = inspect_packet(pkt, DetailLevel.FULL)
    assert "═" in result  # Box drawing separator
    assert "Raw hex:" in result
    assert "I-Am" in result
    assert "Source:" in result
    assert "Destination:" in result


def test_inspector_error_fields():
    """Inspector — error/reject/abort reason shown in normal view."""
    pkt = make_packet(
        apdu_pdu_type=5,
        apdu_service_name="ReadProperty",
        apdu_error_class=1,
        apdu_error_class_name="Object",
        apdu_error_code=31,
    )
    result = inspect_packet(pkt, DetailLevel.NORMAL)
    assert "error=Object/31" in result


def test_inspector_parse_error():
    """Inspector — parse error shown when present."""
    pkt = make_packet(
        skip_apdu=True,
        parse_error="APDU: data too short",
    )
    result = inspect_packet(pkt, DetailLevel.NORMAL)
    assert "Parse error" in result
    assert "APDU: data too short" in result


def test_inspector_dict():
    """Inspector — dict serialization has all layer keys."""
    pkt = make_packet(
        apdu_service_name="Who-Is",
        obj_type=8, obj_type_name="Device", obj_instance=100,
    )
    d = inspect_packet_dict(pkt)
    assert "bvlc" in d
    assert "npdu" in d
    assert "apdu" in d
    assert d["source_ip"] == "192.168.1.10"
    assert d["raw_hex"] is not None


def test_inspector_network_msg():
    """Inspector — network message shown correctly without APDU."""
    pkt = make_packet(
        npdu_is_network_msg=True,
        npdu_net_msg_type=0x00,
        npdu_net_msg_name="Who-Is-Router-To-Network",
        skip_apdu=True,
    )
    result = inspect_packet(pkt, DetailLevel.NORMAL)
    assert "NETWORK-MSG: Who-Is-Router-To-Network" in result


def test_inspector_bvlc_only():
    """Inspector — BVLC-only packet (no NPDU/APDU) renders cleanly."""
    pkt = make_packet(
        bvlc_function=0x00,
        bvlc_function_name="BVLC-Result",
        bvlc_result_code=0,
        bvlc_result_name="Successful-Completion",
        skip_npdu=True,
        skip_apdu=True,
    )
    result = inspect_packet(pkt, DetailLevel.NORMAL)
    assert "BVLC:" in result
    assert "BVLC-Result" in result
    assert "Successful-Completion" in result
    assert "NPDU:" not in result
    assert "APDU:" not in result


if _DIRECT_RUN:
    for fn in [
        test_inspector_summary,
        test_inspector_normal,
        test_inspector_full,
        test_inspector_error_fields,
        test_inspector_parse_error,
        test_inspector_dict,
        test_inspector_network_msg,
        test_inspector_bvlc_only,
    ]:
        run_test(fn.__doc__.strip(), fn)


# ─── GROUP 5: Integration — All Modules Together ─────────────────────────────

if _DIRECT_RUN: print("\n── Integration ──")


def test_integration_full_pipeline():
    """Integration — all modules process the same packet stream correctly."""
    reg = DeviceRegistry()
    stats = TrafficStats()
    detector = AnomalyDetector(chatty_pps=100, cooldown_seconds=0)

    now = 10000.0

    # Simulate a realistic packet sequence
    # 1. Device discovery (I-Am from 3 devices)
    for i, instance in enumerate([100, 200, 300]):
        pkt = make_iam(instance, f"192.168.1.{10 + i * 10}", ts=now + i)
        reg.process_packet(pkt)
        stats.process_packet(pkt)
        detector.process_packet(pkt)

    # 2. ReadProperty requests to device 100
    for i in range(5):
        pkt = make_packet(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            apdu_pdu_type=0,
            apdu_service_choice=12,
            apdu_service_name="ReadProperty",
            apdu_is_confirmed=True,
            apdu_invoke_id=i,
            ts=now + 10 + i,
        )
        reg.process_packet(pkt)
        stats.process_packet(pkt)
        detector.process_packet(pkt)

    # 3. Complex-ACK responses
    for i in range(5):
        pkt = make_packet(
            src_ip="192.168.1.20",
            dst_ip="192.168.1.10",
            apdu_pdu_type=3,
            apdu_service_choice=12,
            apdu_service_name="ReadProperty",
            apdu_is_confirmed=True,
            apdu_invoke_id=i,
            ts=now + 10 + i + 0.01,
        )
        reg.process_packet(pkt)
        stats.process_packet(pkt)
        detector.process_packet(pkt)

    # Verify device registry
    assert reg.get_device_count() == 3
    dev100 = reg.get_device(100)
    assert dev100.packet_count > 0  # I-Am + attributed traffic

    # Verify traffic stats
    assert stats.total_packets == 13  # 3 I-Am + 5 RP + 5 ACK
    summary = stats.get_summary()
    assert summary["confirmed_count"] == 5  # only type 0 counted
    talkers = stats.get_top_talkers(n=2)
    assert len(talkers) == 2

    # Verify no anomalies (normal traffic)
    assert detector.get_anomaly_count() == 0


def test_integration_anomaly_during_capture():
    """Integration — anomaly detected mid-stream affects stats."""
    reg = DeviceRegistry()
    stats = TrafficStats()
    detector = AnomalyDetector(error_pps=3, window_seconds=1.0, cooldown_seconds=0)

    now = 20000.0

    # Normal traffic
    reg.process_packet(make_iam(100, "192.168.1.20", ts=now))
    stats.process_packet(make_iam(100, "192.168.1.20", ts=now))

    # Error burst
    for i in range(5):
        pkt = make_packet(
            apdu_pdu_type=5,
            apdu_service_name="ReadProperty",
            apdu_error_class=1,
            apdu_error_class_name="Object",
            apdu_error_code=31,
            ts=now + 1 + i * 0.1,
        )
        stats.process_packet(pkt)
        detector.process_packet(pkt)

    assert stats.get_summary()["error_count"] == 5
    assert detector.get_anomaly_count() > 0
    errors = [a for a in detector.get_recent_anomalies()
              if a.type == AnomalyType.HIGH_ERROR_RATE]
    assert len(errors) >= 1


if _DIRECT_RUN:
    for fn in [
        test_integration_full_pipeline,
        test_integration_anomaly_during_capture,
    ]:
        run_test(fn.__doc__.strip(), fn)

    # Summary
    total = passed + failed
    print(f"\n{'=' * 60}")
    print(f"  {passed}/{total} tests passed", end="")
    if failed:
        print(f"  ({failed} FAILED)")
    else:
        print("  — all clear!")
    print(f"{'=' * 60}")
    exit(0 if failed == 0 else 1)

