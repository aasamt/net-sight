#!/usr/bin/env python3
"""Generate a sample BACnet/IP pcap with 4 devices, including duplicate device IDs.

Devices:
  Device-1: 192.168.1.10 — sends Who-Is (broadcast)
  Device-2: 192.168.1.20 — I-Am, device instance 200, vendor 7
  Device-3: 192.168.1.30 — I-Am, device instance 200, vendor 5  (DUPLICATE ID!)
  Device-4: 192.168.1.40 — I-Am, device instance 300, vendor 10
"""

import struct
import time

from scapy.all import IP, UDP, Ether, wrpcap

BACNET_PORT = 47808  # 0xBAC0
BROADCAST_IP = "192.168.1.255"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# Device definitions
DEVICES = {
    1: {"ip": "192.168.1.10", "mac": "00:1a:2b:01:01:01"},
    2: {"ip": "192.168.1.20", "mac": "00:1a:2b:02:02:02"},
    3: {"ip": "192.168.1.30", "mac": "00:1a:2b:03:03:03"},
    4: {"ip": "192.168.1.40", "mac": "00:1a:2b:04:04:04"},
    5: {"ip": "192.168.1.50", "mac": "00:1a:2b:03:03:05"},
    6: {"ip": "192.168.1.60", "mac": "00:1a:2b:04:04:06"},
    7: {"ip": "192.168.1.70", "mac": "00:1a:2b:03:03:07"},
    8: {"ip": "192.168.1.80", "mac": "00:1a:2b:04:04:08"},
}


def make_bvlc_broadcast(payload: bytes) -> bytes:
    """Wrap NPDU+APDU in a BVLC Original-Broadcast-NPDU header."""
    total_len = 4 + len(payload)
    return struct.pack("!BBH", 0x81, 0x0B, total_len) + payload


def make_who_is() -> bytes:
    """Build a Who-Is packet (no range limits).

    NPDU: version=0x01, control=0x04 (expecting reply)
    APDU: PDU type=0x10 (Unconfirmed-Request), service=0x08 (Who-Is)
    """
    npdu = bytes([0x01, 0x04])
    apdu = bytes([0x10, 0x08])
    return make_bvlc_broadcast(npdu + apdu)


def make_iam(device_instance: int, vendor_id: int, max_apdu: int = 1476) -> bytes:
    """Build an I-Am packet.

    NPDU: version=0x01, control=0x00
    APDU: PDU type=0x10 (Unconfirmed-Request), service=0x00 (I-Am)
      - Object Identifier: app tag 12 (0xC4), 4 bytes (Device object type=8)
      - Max APDU Length Accepted: app tag 2 (0x22), 2 bytes
      - Segmentation Supported: app tag 9 (0x91), 1 byte (3=no-segmentation)
      - Vendor ID: app tag 2, 1 or 2 bytes depending on value
    """
    npdu = bytes([0x01, 0x00])

    # Object identifier: device type (8) << 22 | instance
    obj_id = (8 << 22) | (device_instance & 0x3FFFFF)
    obj_id_bytes = struct.pack("!I", obj_id)

    # Max APDU length accepted (unsigned, 2 bytes)
    max_apdu_bytes = struct.pack("!H", max_apdu)

    # Build APDU
    apdu = bytes([0x10, 0x00])  # Unconfirmed-Request, I-Am
    apdu += bytes([0xC4]) + obj_id_bytes  # Object Identifier (app tag 12, len 4)
    apdu += bytes([0x22]) + max_apdu_bytes  # Max APDU Length (app tag 2, len 2)
    apdu += bytes([0x91, 0x03])  # Segmentation Supported (app tag 9, len 1, value=3)

    # Vendor ID — use 1 byte if <= 255, 2 bytes otherwise
    if vendor_id <= 255:
        apdu += bytes([0x21, vendor_id & 0xFF])
    else:
        apdu += bytes([0x22]) + struct.pack("!H", vendor_id)

    return make_bvlc_broadcast(npdu + apdu)


def build_packet(src_ip: str, src_mac: str, dst_ip: str, dst_mac: str, payload: bytes):
    """Build a full Ethernet/IP/UDP/BACnet packet."""
    pkt = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=BACNET_PORT, dport=BACNET_PORT)
        / payload
    )
    return pkt


def main():
    packets = []
    base_time = time.time()

    # 1) Device-1 sends Who-Is broadcast
    who_is_payload = make_who_is()
    pkt = build_packet(
        src_ip=DEVICES[1]["ip"],
        src_mac=DEVICES[1]["mac"],
        dst_ip=BROADCAST_IP,
        dst_mac=BROADCAST_MAC,
        payload=who_is_payload,
    )
    pkt.time = base_time
    packets.append(pkt)

    # 2) Device-2 responds with I-Am (device instance 200, vendor 7)
    iam2 = make_iam(device_instance=200, vendor_id=7)
    pkt2 = build_packet(
        src_ip=DEVICES[2]["ip"],
        src_mac=DEVICES[2]["mac"],
        dst_ip=BROADCAST_IP,
        dst_mac=BROADCAST_MAC,
        payload=iam2,
    )
    pkt2.time = base_time + 0.05
    packets.append(pkt2)

    # 3) Device-3 responds with I-Am (device instance 200, vendor 5 — DUPLICATE ID!)
    iam3 = make_iam(device_instance=200, vendor_id=5)
    pkt3 = build_packet(
        src_ip=DEVICES[3]["ip"],
        src_mac=DEVICES[3]["mac"],
        dst_ip=BROADCAST_IP,
        dst_mac=BROADCAST_MAC,
        payload=iam3,
    )
    pkt3.time = base_time + 0.10
    packets.append(pkt3)

    # 4) Device-4 responds with I-Am (device instance 300, vendor 10)
    iam4 = make_iam(device_instance=300, vendor_id=10)
    pkt4 = build_packet(
        src_ip=DEVICES[4]["ip"],
        src_mac=DEVICES[4]["mac"],
        dst_ip=BROADCAST_IP,
        dst_mac=BROADCAST_MAC,
        payload=iam4,
    )
    pkt4.time = base_time + 0.15
    packets.append(pkt4)

    # 5) Device-5 responds with I-Am (device instance 500, vendor 10)
    iam5 = make_iam(device_instance=500, vendor_id=10)
    pkt5 = build_packet(
        src_ip=DEVICES[5]["ip"],
        src_mac=DEVICES[5]["mac"],
        dst_ip=BROADCAST_IP,
        dst_mac=BROADCAST_MAC,
        payload=iam5,
    )
    pkt5.time = base_time + 0.20
    packets.append(pkt5)

    # 6) Device-6 responds with I-Am (device instance 500, vendor 10)   
    iam6 = make_iam(device_instance=500, vendor_id=10)
    pkt6 = build_packet(
        src_ip=DEVICES[6]["ip"],
        src_mac=DEVICES[6]["mac"],
        dst_ip=BROADCAST_IP,
        dst_mac=BROADCAST_MAC,
        payload=iam6,
    )
    pkt6.time = base_time + 0.25
    packets.append(pkt6)

    # 7) Device-7 responds with I-Am (device instance 700, vendor 10)
    iam7 = make_iam(device_instance=700, vendor_id=10)
    pkt7 = build_packet(
        src_ip=DEVICES[7]["ip"],
        src_mac=DEVICES[7]["mac"],
        dst_ip=BROADCAST_IP,
        dst_mac=BROADCAST_MAC,
        payload=iam7,
    )
    pkt7.time = base_time + 0.30
    packets.append(pkt7)

    # 8) Device-8 responds with I-Am (device instance 800, vendor 10)
    iam8 = make_iam(device_instance=700, vendor_id=10)
    pkt8 = build_packet(
        src_ip=DEVICES[8]["ip"],
        src_mac=DEVICES[8]["mac"],
        dst_ip=BROADCAST_IP,
        dst_mac=BROADCAST_MAC,
        payload=iam8,
    )
    pkt8.time = base_time + 0.35
    packets.append(pkt8)

    # Write pcap
    output = "samples/duplicate_device_id.pcap"
    wrpcap(output, packets)
    print(f"Wrote {len(packets)} packets to {output}")
    print()
    print("Packet summary:")
    for i, p in enumerate(packets, 1):
        src = p[IP].src
        dst = p[IP].dst
        payload_hex = bytes(p[UDP].payload).hex()
        print(f"  #{i}  {src} → {dst}  [{len(bytes(p[UDP].payload))} bytes]  {payload_hex}")


if __name__ == "__main__":
    main()
