#!/usr/bin/env python3
"""Generate a sample BACnet/IP pcap simulating multiple broadcast storm patterns.

Scenario (8 phases):
  1. Normal discovery: Device-A sends Who-Is, Devices B/C/D reply with I-Am  (4 packets)
  2. Quiet gap (2 seconds)
  3. Discovery flood: Device-E malfunctions and floods Who-Is at ~60 pps,
     multiple devices respond with I-Am  (classic broadcast storm)
  4. Brief calm (2 seconds)
  5. TimeSynchronization flood: Device-H floods TimeSynchronization at ~15 pps
  6. Brief calm (2 seconds)
  7. Router discovery flood: Device-I floods Who-Is-Router-To-Network (NPDU, no APDU)
  8. Recovery: a few normal packets

Devices:
  Device-A: 192.168.1.10 — normal Who-Is initiator
  Device-B: 192.168.1.20 — normal responder, instance 100
  Device-C: 192.168.1.30 — normal responder, instance 200
  Device-D: 192.168.1.40 — normal responder, instance 300
  Device-E: 192.168.1.50 — malfunctioning controller, floods Who-Is
  Device-F: 192.168.1.60 — responds during storm, instance 400
  Device-G: 192.168.1.70 — responds during storm, instance 500
  Device-H: 192.168.1.80 — misconfigured time master, floods TimeSynchronization
  Device-I: 192.168.1.90 — misconfigured router, floods Who-Is-Router-To-Network

Usage:
  uv run python samples/gen_broadcast_storm.py
"""

import struct
import time

from scapy.all import IP, UDP, Ether, wrpcap

BACNET_PORT = 47808  # 0xBAC0
BROADCAST_IP = "192.168.1.255"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

DEVICES = {
    "A": {"ip": "192.168.1.10", "mac": "00:1a:2b:01:01:01"},
    "B": {"ip": "192.168.1.20", "mac": "00:1a:2b:02:02:02"},
    "C": {"ip": "192.168.1.30", "mac": "00:1a:2b:03:03:03"},
    "D": {"ip": "192.168.1.40", "mac": "00:1a:2b:04:04:04"},
    "E": {"ip": "192.168.1.50", "mac": "00:1a:2b:05:05:05"},  # discovery storm
    "F": {"ip": "192.168.1.60", "mac": "00:1a:2b:06:06:06"},
    "G": {"ip": "192.168.1.70", "mac": "00:1a:2b:07:07:07"},
    "H": {"ip": "192.168.1.80", "mac": "00:1a:2b:08:08:08"},  # timesync storm
    "I": {"ip": "192.168.1.90", "mac": "00:1a:2b:09:09:09"},  # router discovery storm
}


# ── BVLC helpers ─────────────────────────────────────────────────────────────

def make_bvlc_broadcast(payload: bytes) -> bytes:
    """Wrap NPDU+APDU in a BVLC Original-Broadcast-NPDU header (0x0B)."""
    total_len = 4 + len(payload)
    return struct.pack("!BBH", 0x81, 0x0B, total_len) + payload


# ── APDU helpers ─────────────────────────────────────────────────────────────

def _encode_context_unsigned(tag_num: int, value: int) -> bytes:
    """Encode a context-tagged unsigned integer (BACnet style)."""
    if value <= 0xFF:
        return bytes([(tag_num << 4) | 0x08 | 1, value])
    elif value <= 0xFFFF:
        return bytes([(tag_num << 4) | 0x08 | 2]) + struct.pack("!H", value)
    else:
        return bytes([(tag_num << 4) | 0x08 | 4]) + struct.pack("!I", value)


def make_who_is(low_limit: int | None = None, high_limit: int | None = None) -> bytes:
    """Build a Who-Is packet (Unconfirmed-Request, service 0x08).

    NPDU: version=0x01, control=0x04 (expecting reply)
    """
    npdu = bytes([0x01, 0x04])
    apdu = bytes([0x10, 0x08])
    if low_limit is not None and high_limit is not None:
        apdu += _encode_context_unsigned(0, low_limit)
        apdu += _encode_context_unsigned(1, high_limit)
    return make_bvlc_broadcast(npdu + apdu)


def make_iam(device_instance: int, vendor_id: int, max_apdu: int = 1476) -> bytes:
    """Build an I-Am packet (Unconfirmed-Request, service 0x00)."""
    npdu = bytes([0x01, 0x00])
    obj_id = (8 << 22) | (device_instance & 0x3FFFFF)
    obj_id_bytes = struct.pack("!I", obj_id)

    apdu = bytes([0x10, 0x00])
    apdu += bytes([0xC4]) + obj_id_bytes
    apdu += bytes([0x22]) + struct.pack("!H", max_apdu)
    apdu += bytes([0x91, 0x03])
    if vendor_id <= 255:
        apdu += bytes([0x21, vendor_id & 0xFF])
    else:
        apdu += bytes([0x22]) + struct.pack("!H", vendor_id)

    return make_bvlc_broadcast(npdu + apdu)


def make_time_sync(year: int = 2026, month: int = 2, day: int = 19,
                   hour: int = 12, minute: int = 0, second: int = 0,
                   hundredths: int = 0) -> bytes:
    """Build a TimeSynchronization packet (Unconfirmed-Request, service 0x06).

    BACnet TimeSynchronization carries a Date + Time application-tagged pair.
    Date: app tag 10 (0xA4), 4 bytes: year-1900, month, day, day-of-week
    Time: app tag 11 (0xB4), 4 bytes: hour, minute, second, hundredths
    """
    npdu = bytes([0x01, 0x00])
    apdu = bytes([0x10, 0x06])  # Unconfirmed-Request, TimeSynchronization

    # Date: app tag 10, len 4
    apdu += bytes([0xA4])
    apdu += bytes([year - 1900, month, day, 0xFF])  # 0xFF = unspecified day-of-week

    # Time: app tag 11, len 4
    apdu += bytes([0xB4])
    apdu += bytes([hour, minute, second, hundredths])

    return make_bvlc_broadcast(npdu + apdu)


def make_who_is_router(network: int | None = None) -> bytes:
    """Build a Who-Is-Router-To-Network packet (NPDU network message 0x00, no APDU).

    BVLC: Original-Broadcast-NPDU (0x0B)
    NPDU: version=0x01, control=0x80 (network message, bit 7 set)
    Network message type: 0x00 (Who-Is-Router-To-Network)
    Optional 2-byte DNET to query for.
    """
    npdu = bytes([0x01, 0x80, 0x00])
    if network is not None:
        npdu += struct.pack("!H", network)
    return make_bvlc_broadcast(npdu)


def make_i_am_router(*networks: int) -> bytes:
    """Build an I-Am-Router-To-Network packet (NPDU network message 0x01, no APDU).

    Contains a list of 2-byte network numbers the router can reach.
    """
    npdu = bytes([0x01, 0x80, 0x01])
    for net in networks:
        npdu += struct.pack("!H", net)
    return make_bvlc_broadcast(npdu)


# ── Packet builder ───────────────────────────────────────────────────────────

def build_packet(
    src_ip: str, src_mac: str, dst_ip: str, dst_mac: str, payload: bytes
):
    """Build a full Ethernet/IP/UDP/BACnet packet."""
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=BACNET_PORT, dport=BACNET_PORT)
        / payload
    )


def broadcast_pkt(device_key: str, payload: bytes):
    """Shortcut to build a broadcast packet from a named device."""
    dev = DEVICES[device_key]
    return build_packet(dev["ip"], dev["mac"], BROADCAST_IP, BROADCAST_MAC, payload)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    packets = []
    base_time = time.time()
    t = 0.0

    # ── Phase 1: Normal discovery (4 packets over ~1.5 seconds) ──────────
    pkt = broadcast_pkt("A", make_who_is())
    pkt.time = base_time + t
    packets.append(pkt)
    t += 0.3

    pkt = broadcast_pkt("B", make_iam(device_instance=100, vendor_id=5))
    pkt.time = base_time + t
    packets.append(pkt)
    t += 0.3

    pkt = broadcast_pkt("C", make_iam(device_instance=200, vendor_id=7))
    pkt.time = base_time + t
    packets.append(pkt)
    t += 0.3

    pkt = broadcast_pkt("D", make_iam(device_instance=300, vendor_id=10))
    pkt.time = base_time + t
    packets.append(pkt)
    t += 0.6

    phase1_count = len(packets)
    print(f"Phase 1 — Normal discovery: {phase1_count} packets, t={t:.1f}s")

    # ── Phase 2: Normal traffic gap ──────────────────────────────────────
    t += 2.0
    print(f"Phase 2 — Quiet gap until t={t:.1f}s")

    # ── Phase 3: Discovery flood (~8 seconds) ───────────────────────────
    storm_start = t
    storm_duration = 8.0
    who_is_interval = 1.0 / 60.0  # ~60 Who-Is/sec from Device-E

    responders = [
        ("B", 100, 5),
        ("C", 200, 7),
        ("D", 300, 10),
        ("F", 400, 12),
        ("G", 500, 15),
    ]
    responder_interval = 0.5
    next_responder_time = {
        key: storm_start + 0.05 * i for i, (key, _, _) in enumerate(responders)
    }

    storm_packets = 0
    who_is_count = 0
    iam_count = 0

    who_is_t = storm_start
    while who_is_t < storm_start + storm_duration:
        low = int((who_is_t - storm_start) * 50) % 4194303
        high = min(low + 1000, 4194303)
        pkt = broadcast_pkt("E", make_who_is(low_limit=low, high_limit=high))
        pkt.time = base_time + who_is_t
        packets.append(pkt)
        storm_packets += 1
        who_is_count += 1

        for key, instance, vendor in responders:
            if who_is_t >= next_responder_time[key]:
                pkt = broadcast_pkt(key, make_iam(device_instance=instance, vendor_id=vendor))
                pkt.time = base_time + who_is_t + 0.001
                packets.append(pkt)
                storm_packets += 1
                iam_count += 1
                next_responder_time[key] += responder_interval

        who_is_t += who_is_interval

    t = storm_start + storm_duration
    print(
        f"Phase 3 — Discovery flood: {storm_packets} packets "
        f"({who_is_count} Who-Is + {iam_count} I-Am), "
        f"t={storm_start:.1f}s–{t:.1f}s"
    )

    # ── Phase 4: Brief calm ──────────────────────────────────────────────
    t += 2.0
    print(f"Phase 4 — Calm until t={t:.1f}s")

    # ── Phase 5: TimeSynchronization flood (~8 seconds at ~20 pps) ───────
    ts_start = t
    ts_duration = 8.0
    ts_interval = 1.0 / 20.0  # ~20 TimeSynchronization/sec from Device-H
    ts_count = 0

    ts_t = ts_start
    sec_counter = 0
    while ts_t < ts_start + ts_duration:
        pkt = broadcast_pkt(
            "H",
            make_time_sync(second=sec_counter % 60, hundredths=int((ts_t * 100) % 100)),
        )
        pkt.time = base_time + ts_t
        packets.append(pkt)
        ts_count += 1
        sec_counter += 1
        ts_t += ts_interval

    t = ts_start + ts_duration
    print(
        f"Phase 5 — TimeSynchronization flood: {ts_count} packets "
        f"(~{ts_count / ts_duration:.0f} pps), t={ts_start:.1f}s–{t:.1f}s"
    )

    # ── Phase 6: Brief calm ──────────────────────────────────────────────
    t += 2.0
    print(f"Phase 6 — Calm until t={t:.1f}s")

    # ── Phase 7: Router discovery flood (~8 seconds at ~30 pps) ──────────
    rd_start = t
    rd_duration = 8.0
    rd_interval = 1.0 / 30.0  # ~30 Who-Is-Router/sec from Device-I
    rd_count = 0
    rd_response_count = 0

    rd_t = rd_start
    net_counter = 0
    next_response = rd_start + 0.2
    while rd_t < rd_start + rd_duration:
        net = (net_counter % 100) + 1
        pkt = broadcast_pkt("I", make_who_is_router(network=net))
        pkt.time = base_time + rd_t
        packets.append(pkt)
        rd_count += 1
        net_counter += 1

        # Device-D responds frequently as a router during the flood
        if rd_t >= next_response:
            pkt = broadcast_pkt("D", make_i_am_router(1, 2, 3))
            pkt.time = base_time + rd_t + 0.001
            packets.append(pkt)
            rd_response_count += 1
            next_response += 0.5  # respond every ~0.5s

        rd_t += rd_interval

    t = rd_start + rd_duration
    print(
        f"Phase 7 — Router discovery flood: {rd_count + rd_response_count} packets "
        f"(~{(rd_count + rd_response_count) / rd_duration:.0f} pps), "
        f"t={rd_start:.1f}s–{t:.1f}s"
    )

    # ── Phase 8: Recovery ────────────────────────────────────────────────
    t += 1.0

    pkt = broadcast_pkt("A", make_who_is())
    pkt.time = base_time + t
    packets.append(pkt)
    t += 0.5

    pkt = broadcast_pkt("B", make_iam(device_instance=100, vendor_id=5))
    pkt.time = base_time + t
    packets.append(pkt)
    t += 0.5

    pkt = broadcast_pkt("D", make_iam(device_instance=300, vendor_id=10))
    pkt.time = base_time + t
    packets.append(pkt)

    print(f"Phase 8 — Recovery: 3 packets, total duration ~{t:.1f}s")
    print()

    # Sort all packets by timestamp
    packets.sort(key=lambda p: p.time)

    # Write pcap
    output = "samples/broadcast_storm.pcap"
    wrpcap(output, packets)
    print(f"Wrote {len(packets)} packets to {output}")
    print()

    # Summary
    duration = packets[-1].time - packets[0].time
    avg_pps = len(packets) / duration if duration > 0 else 0

    print(f"Total packets:         {len(packets)}")
    print(f"  Discovery flood:     {who_is_count} Who-Is + {iam_count} I-Am")
    print(f"  TimeSynchronization: {ts_count}")
    print(f"  Router discovery:    {rd_count} Who-Is-Router + {rd_response_count} I-Am-Router")
    print(f"  Normal/recovery:     {phase1_count + 3}")
    print(f"Duration:              {duration:.2f}s")
    print(f"Average rate:          {avg_pps:.1f} pps")


if __name__ == "__main__":
    main()
