# NetSight — BACnet Network Traffic Analyzer: Research Document

## Table of Contents

1. [BACnet Protocol Overview](#1-bacnet-protocol-overview)
2. [BACnet/IP Packet Structure](#2-bacnetip-packet-structure)
3. [BVLC Layer](#3-bvlc-layer-bacnet-virtual-link-control)
4. [NPDU Layer](#4-npdu-layer-network-protocol-data-unit)
5. [APDU Layer](#5-apdu-layer-application-protocol-data-unit)
6. [BACnet Services](#6-bacnet-services)
7. [BACnet Object Model](#7-bacnet-object-model)
8. [BBMD & Foreign Device Registration](#8-bbmd--foreign-device-registration)
9. [BACnet Data Encoding](#9-bacnet-data-encoding)
10. [Error Handling](#10-error-handling)
11. [Packet Capture Technologies](#11-packet-capture-technologies)
12. [BACpypes3 Reference Architecture](#12-bacpypes3-reference-architecture)
13. [Scapy Packet Capture](#13-scapy-packet-capture)
14. [Desktop App Architecture](#14-desktop-app-architecture-electron--python)
15. [Performance Considerations](#15-performance-considerations)
16. [Data Link / Physical Layers](#16-data-link--physical-layers)

---

## 1. BACnet Protocol Overview

BACnet (Building Automation and Control Network) is defined by **ANSI/ASHRAE Standard 135** and **ISO 16484-5**. It is a communication protocol for building automation covering HVAC, lighting, access control, and fire detection.

- **Protocol Version:** 1
- **Current Protocol Revision:** Up to 29 (ANSI/ASHRAE 135-2024)
- BACnet is an **unconnected, peer network** — any device can send service requests to any other device
- Communication is **unscheduled** with no time-critical operations
- BACnet defines both the **data model** (objects, properties) and the **communication protocol** (services, messages)

---

## 2. BACnet/IP Packet Structure

A BACnet/IP packet sent over **UDP port 47808 (0xBAC0)** consists of three nested layers:

```
┌─────────────────────────────────┐
│  BVLC Header (BACnet Virtual   │  ← Data Link Layer (4+ bytes)
│  Link Control)                  │
├─────────────────────────────────┤
│  NPDU (Network Protocol        │  ← Network Layer (variable)
│  Data Unit)                     │
├─────────────────────────────────┤
│  APDU (Application Protocol    │  ← Application Layer (variable)
│  Data Unit)                     │
└─────────────────────────────────┘
```

- **Max APDU size:** 1476 bytes
- **BACnet/IP MAC address:** 6 bytes (4 for IPv4 address + 2 for UDP port)
- **Default UDP port:** 47808 (0xBAC0)

---

## 3. BVLC Layer (BACnet Virtual Link Control)

### 3.1 Header Format (4-byte minimum)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 byte | Type | Always `0x81` for BACnet/IPv4 |
| 1 | 1 byte | Function | BVLC function code (0x00–0x0C) |
| 2-3 | 2 bytes | Length | Total BVLC message length (big-endian) |

### 3.2 BVLC Function Types

| Code | Name | Description |
|------|------|-------------|
| 0x00 | BVLC-Result | Response to certain BVLC requests |
| 0x01 | Write-Broadcast-Distribution-Table | Write BDT to a BBMD |
| 0x02 | Read-Broadcast-Distribution-Table | Read BDT from a BBMD |
| 0x03 | Read-Broadcast-Distribution-Table-Ack | Response with BDT contents |
| 0x04 | Forwarded-NPDU | NPDU forwarded by a BBMD (includes 6-byte original source B/IP address) |
| 0x05 | Register-Foreign-Device | Register as foreign device with a BBMD (includes 2-byte TTL) |
| 0x06 | Read-Foreign-Device-Table | Read FDT from a BBMD |
| 0x07 | Read-Foreign-Device-Table-Ack | Response with FDT contents |
| 0x08 | Delete-Foreign-Device-Table-Entry | Delete an FDT entry |
| 0x09 | Distribute-Broadcast-To-Network | Request BBMD to distribute broadcast |
| 0x0A | Original-Unicast-NPDU | Standard unicast message |
| 0x0B | Original-Broadcast-NPDU | Standard local broadcast |
| 0x0C | Secure-BVLL | BACnet Secure Connect BVLL message |

### 3.3 BVLC Result Codes

| Code | Meaning |
|------|---------|
| 0x0000 | Successful Completion |
| 0x0010 | Write-Broadcast-Distribution-Table NAK |
| 0x0020 | Read-Broadcast-Distribution-Table NAK |
| 0x0030 | Register-Foreign-Device NAK |
| 0x0040 | Read-Foreign-Device-Table NAK |
| 0x0050 | Delete-Foreign-Device-Table-Entry NAK |
| 0x0060 | Distribute-Broadcast-To-Network NAK |

---

## 4. NPDU Layer (Network Protocol Data Unit)

### 4.1 NPCI Wire Format

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 1 byte | Version | Always `0x01` |
| 1 | 1 byte | Control | Bit flags (see below) |
| 2+ | 2 bytes | DNET | Destination network (if bit 5 set) |
| var | 1 byte | DLEN | Destination MAC length (0 = broadcast) |
| var | DLEN bytes | DADR | Destination MAC address |
| var | 2 bytes | SNET | Source network (if bit 3 set) |
| var | 1 byte | SLEN | Source MAC length |
| var | SLEN bytes | SADR | Source MAC address |
| var | 1 byte | Hop Count | Present if DNET present (default 255) |
| var | 1 byte | Message Type | Present if bit 7 set (network layer message) |
| var | 2 bytes | Vendor ID | Present if message type >= 0x80 |

### 4.2 Control Byte Flags

| Bit | Mask | Meaning |
|-----|------|---------|
| 7 | 0x80 | 1 = Network layer message, 0 = APDU follows |
| 5 | 0x20 | DNET/DADR/Hop Count present |
| 3 | 0x08 | SNET/SADR present |
| 2 | 0x04 | Data expecting reply |
| 1-0 | 0x03 | Network priority (see below) |

### 4.3 Network Priority Levels

| Code | Priority |
|------|----------|
| 0 | Normal |
| 1 | Urgent |
| 2 | Critical Equipment |
| 3 | Life Safety |

### 4.4 Network Layer Message Types

| Code | Name |
|------|------|
| 0x00 | Who-Is-Router-To-Network |
| 0x01 | I-Am-Router-To-Network |
| 0x02 | I-Could-Be-Router-To-Network |
| 0x03 | Reject-Message-To-Network |
| 0x04 | Router-Busy-To-Network |
| 0x05 | Router-Available-To-Network |
| 0x06 | Initialize-Routing-Table |
| 0x07 | Initialize-Routing-Table-Ack |
| 0x08 | Establish-Connection-To-Network |
| 0x09 | Disconnect-Connection-To-Network |
| 0x0A | Challenge-Request |
| 0x0B | Security-Payload |
| 0x0C | Security-Response |
| 0x0D | Request-Key-Update |
| 0x0E | Update-Key-Set |
| 0x0F | Update-Distribution-Key |
| 0x10 | Request-Master-Key |
| 0x11 | Set-Master-Key |
| 0x12 | What-Is-Network-Number |
| 0x13 | Network-Number-Is |
| 0x14–0x7F | Reserved by ASHRAE |
| 0x80–0xFF | Vendor proprietary messages |

### 4.5 Network Reject Reasons

| Code | Reason |
|------|--------|
| 0 | Unknown Error |
| 1 | No Route |
| 2 | Router Busy |
| 3 | Unknown Message Type |
| 4 | Message Too Long |
| 5 | BACnet Security Error |
| 6 | Bad Address |

### 4.6 Network Number Constants

- `0x0000` = Local network
- `0xFFFF` = Broadcast to all networks

---

## 5. APDU Layer (Application Protocol Data Unit)

### 5.1 PDU Types

The first byte encodes the PDU type in the upper nibble: `pduType = (byte >> 4) & 0x0F`

| Code | PDU Type | Description |
|------|----------|-------------|
| 0 | Confirmed-Service-Request | Request requiring a response |
| 1 | Unconfirmed-Service-Request | Request not requiring a response |
| 2 | Simple-ACK | Simple acknowledgment |
| 3 | Complex-ACK | Acknowledgment with data |
| 4 | Segment-ACK | Acknowledgment of a segment |
| 5 | Error | Error response |
| 6 | Reject | Request rejected (protocol error) |
| 7 | Abort | Transaction aborted |

### 5.2 Confirmed Request Header

| Byte | Content |
|------|---------|
| 0 | Type<<4 + flags (SEG=0x08, MOR=0x04, SA=0x02) |
| 1 | MaxSegs<<4 + MaxResp |
| 2 | Invoke ID |
| 3-4 | Seq + Window (if segmented) |
| last | Service Choice |

### 5.3 Unconfirmed Request Header

| Byte | Content |
|------|---------|
| 0 | 0x10 |
| 1 | Service Choice |

### 5.4 Segmentation

```
Segmentation Support:
  0 = Can both transmit and receive segments
  1 = Can only transmit segments
  2 = Can only receive segments
  3 = No segmentation support

Max segments accepted: 1–255 (default: 32 when enabled, 1 when disabled)
```

---

## 6. BACnet Services

### 6.1 Confirmed Services

| Code | Service | ACK Type |
|------|---------|----------|
| 0 | AcknowledgeAlarm | SimpleAck |
| 1 | ConfirmedCOVNotification | SimpleAck |
| 2 | ConfirmedEventNotification | SimpleAck |
| 3 | GetAlarmSummary | ComplexAck |
| 4 | GetEnrollmentSummary | ComplexAck |
| 5 | SubscribeCOV | SimpleAck |
| 6 | AtomicReadFile | ComplexAck |
| 7 | AtomicWriteFile | ComplexAck |
| 8 | AddListElement | SimpleAck |
| 9 | RemoveListElement | SimpleAck |
| 10 | CreateObject | ComplexAck |
| 11 | DeleteObject | SimpleAck |
| **12** | **ReadProperty** | **ComplexAck** |
| 13 | ReadPropertyConditional | ComplexAck |
| **14** | **ReadPropertyMultiple** | **ComplexAck** |
| **15** | **WriteProperty** | **SimpleAck** |
| 16 | WritePropertyMultiple | SimpleAck |
| 17 | DeviceCommunicationControl | SimpleAck |
| 18 | ConfirmedPrivateTransfer | ComplexAck |
| 19 | ConfirmedTextMessage | SimpleAck |
| 20 | ReinitializeDevice | SimpleAck |
| 21 | VT-Open | ComplexAck |
| 22 | VT-Close | SimpleAck |
| 23 | VT-Data | ComplexAck |
| 24 | Authenticate | — |
| 25 | RequestKey | — |
| 26 | ReadRange | ComplexAck |
| 27 | LifeSafetyOperation | SimpleAck |
| 28 | SubscribeCOVProperty | SimpleAck |
| 29 | GetEventInformation | ComplexAck |
| 30 | SubscribeCOVPropertyMultiple | SimpleAck |
| 31 | ConfirmedCOVNotificationMultiple | SimpleAck |
| 32 | ConfirmedAuditNotification | — |
| 33 | AuditLogQuery | ComplexAck |
| 34 | AuthRequest | — |

### 6.2 Unconfirmed Services

| Code | Service |
|------|---------|
| **0** | **I-Am** |
| 1 | I-Have |
| **2** | **UnconfirmedCOVNotification** |
| 3 | UnconfirmedEventNotification |
| 4 | UnconfirmedPrivateTransfer |
| 5 | UnconfirmedTextMessage |
| 6 | TimeSynchronization |
| **7** | **Who-Has** |
| **8** | **Who-Is** |
| 9 | UTC-TimeSynchronization |
| 10 | WriteGroup |
| 11 | UnconfirmedCOVNotificationMultiple |
| 12 | UnconfirmedAuditNotification |
| 13 | Who-Am-I |
| 14 | You-Are |

---

## 7. BACnet Object Model

### 7.1 Object Types

| Code | Object Type |
|------|-------------|
| 0 | Analog Input |
| 1 | Analog Output |
| 2 | Analog Value |
| 3 | Binary Input |
| 4 | Binary Output |
| 5 | Binary Value |
| 6 | Calendar |
| 7 | Command |
| 8 | **Device** |
| 9 | Event Enrollment |
| 10 | File |
| 11 | Group |
| 12 | Loop |
| 13 | Multi-state Input |
| 14 | Multi-state Output |
| 15 | Notification Class |
| 16 | Program |
| 17 | Schedule |
| 18 | Averaging |
| 19 | Multi-state Value |
| 20 | Trend Log |
| 21 | Life Safety Point |
| 22 | Life Safety Zone |
| 23 | Accumulator |
| 24 | Pulse Converter |
| 25 | Event Log |
| 26 | Global Group |
| 27 | Trend Log Multiple |
| 28 | Load Control |
| 29 | Structured View |
| 30 | Access Door |
| 31 | Timer |
| 32–36 | Access Control objects |
| 37 | Access Zone |
| 38 | Network Security |
| 39–50 | Value objects (BitString, CharacterString, Date, DateTime, Integer, etc.) |
| 51 | Notification Forwarder |
| 52 | Alert Enrollment |
| 53 | Channel |
| 54 | Lighting Output |
| 55 | Binary Lighting Output |
| 56 | Network Port |
| 57–59 | Elevator/Escalator/Lift |
| 60 | Staging |
| 61–64 | Audit/Color objects |
| 65–127 | Reserved (ASHRAE) |
| 128–1023 | **Proprietary range** |

### 7.2 Object Identifier Encoding

Object identifiers are 32-bit values:
- **Bits 22–31** (10 bits): Object Type (0–1023)
- **Bits 0–21** (22 bits): Instance Number (0–4,194,303)

```
MAX_INSTANCE = 0x3FFFFF (4,194,303)
MAX_OBJECT_TYPE = 0x3FF (1,023)

Encoding: (object_type << 22) | instance_number
```

### 7.3 Key Property Identifiers

| Code | Property |
|------|----------|
| 8 | All |
| 28 | Description |
| 36 | Event-State |
| 75 | **Object-Identifier** |
| 76 | Object-List |
| 77 | **Object-Name** |
| 79 | **Object-Type** |
| 81 | Out-Of-Service |
| 85 | **Present-Value** |
| 87 | Priority-Array |
| 103 | Reliability |
| 107 | Segmentation-Supported |
| 111 | Status-Flags |
| 112 | System-Status |
| 117 | Units |
| 120 | Vendor-Identifier |
| 121 | Vendor-Name |
| 139 | Protocol-Revision |
| 155 | Database-Revision |
| 168 | Profile-Name |
| 371 | Property-List |
| 399 | APDU-Length |
| 400 | IP-Address |
| 408 | BACnet-IP-Mode |
| 412 | BACnet-IP-UDP-Port |
| 423 | MAC-Address |
| 425 | Network-Number |
| 427 | Network-Type |
| 0–511 | Reserved (ASHRAE) |
| 512–4194303 | **Proprietary range** |

### 7.4 Device Object Key Properties

`DeviceObject` properties include: `systemStatus`, `vendorName`, `vendorIdentifier`, `modelName`, `firmwareRevision`, `protocolVersion`, `protocolRevision`, `protocolServicesSupported`, `objectList`, `maxApduLengthAccepted`, `segmentationSupported`, `databaseRevision`, `activeCovSubscriptions`.

### 7.5 Priority Array (Commandable Objects)

BACnet commandable objects support 16 priority levels:
- **Priority 1:** Manual Life Safety (highest)
- **Priority 2:** Automatic Life Safety
- **Priority 5:** Critical Equipment Controls
- **Priority 6:** Minimum On/Off
- **Priority 8:** Manual Operator
- **Priority 16:** Available (lowest / default)

---

## 8. BBMD & Foreign Device Registration

BACnet/IP uses **UDP port 47808 (0xBAC0)** by default. BACnet broadcasts don't traverse IP subnets natively, so **BBMDs** (BACnet Broadcast Management Devices) solve this.

### 8.1 Broadcast Distribution Table (BDT)

Each BDT entry consists of:
- **6-byte B/IP address** (4-byte IPv4 + 2-byte UDP port)
- **4-byte broadcast distribution mask**
- Total: 10 bytes per entry

### 8.2 Foreign Device Table (FDT)

Each FDT entry consists of:
- **6-byte B/IP address** of the registrant
- **2-byte Time-to-Live** (TTL) value from registration
- **2-byte remaining seconds** before the entry is purged
- Total: 10 bytes per entry. The BBMD adds a 30-second grace period to the TTL.

### 8.3 BACnet/IP Modes

| Code | Mode |
|------|------|
| 0 | Normal |
| 1 | Foreign |
| 2 | BBMD |

---

## 9. BACnet Data Encoding

### 9.1 Application Tags

| Tag | Data Type |
|-----|-----------|
| 0 | Null |
| 1 | Boolean |
| 2 | Unsigned Integer |
| 3 | Signed Integer |
| 4 | Real (float) |
| 5 | Double |
| 6 | Octet String |
| 7 | Character String |
| 8 | Bit String |
| 9 | Enumerated |
| 10 | Date |
| 11 | Time |
| 12 | BACnetObjectIdentifier |
| 13–15 | Reserved |

---

## 10. Error Handling

### 10.1 Error Classes

| Code | Class |
|------|-------|
| 0 | Device |
| 1 | Object |
| 2 | Property |
| 3 | Resources |
| 4 | Security |
| 5 | Services |
| 6 | VT |
| 7 | Communication |
| 64–65535 | Proprietary |

### 10.2 Key Error Codes (partial — 229+ defined)

| Code | Error |
|------|-------|
| 0 | Other |
| 1 | Authentication-Failed |
| 2 | Configuration-In-Progress |
| 3 | Device-Busy |
| 9 | Invalid-Data-Type |
| 25 | Operational-Problem |
| 27 | Read-Access-Denied |
| 31 | Unknown-Object |
| 32 | Unknown-Property |
| 37 | Value-Out-Of-Range |
| 40 | Write-Access-Denied |
| 42 | Invalid-Array-Index |
| 70 | Unknown-Device |
| 84 | Success |
| 110 | Not-Router-To-DNET |
| 116 | Write-BDT-Failed |
| 118 | Register-Foreign-Device-Failed |
| 121 | Distribute-Broadcast-Failed |
| 131 | Internal-Error |
| 143 | BVLC-Function-Unknown |

### 10.3 Reject Reasons

| Code | Reason |
|------|--------|
| 0 | Other |
| 1 | Buffer-Overflow |
| 2 | Inconsistent-Parameters |
| 3 | Invalid-Parameter-Data-Type |
| 4 | Invalid-Tag |
| 5 | Missing-Required-Parameter |
| 6 | Parameter-Out-Of-Range |
| 7 | Too-Many-Arguments |
| 8 | Undefined-Enumeration |
| 9 | Unrecognized-Service |
| 10 | Invalid-Data-Encoding |
| 64–255 | Proprietary |

### 10.4 Abort Reasons

| Code | Reason |
|------|--------|
| 0 | Other |
| 1 | Buffer-Overflow |
| 2 | Invalid-APDU-In-This-State |
| 3 | Preempted-By-Higher-Priority-Task |
| 4 | Segmentation-Not-Supported |
| 5 | Security-Error |
| 6 | Insufficient-Security |
| 7 | Window-Size-Out-Of-Range |
| 8 | Application-Exceeded-Reply-Time |
| 9 | Out-Of-Resources |
| 10 | TSM-Timeout |
| 11 | APDU-Too-Long |
| 64–255 | Proprietary |

---

## 11. Packet Capture Technologies

### 11.1 Cross-Platform Strategy

| Platform | Backend | Notes |
|----------|---------|-------|
| macOS | libpcap + BPF | Ships with OS; needs `/dev/bpf` access or root |
| Linux | libpcap + AF_PACKET | Can use PACKET_MMAP for zero-copy |
| Windows | Npcap (NDIS 6 LWF) | Must bundle or require Npcap installation |

### 11.2 BPF Filter for BACnet/IP

```
udp port 47808
```

### 11.3 Key Configuration Knobs

- **Snap length:** 65535 (capture full packets)
- **Buffer size:** 2–16MB kernel buffer to handle bursts
- **Immediate mode:** Deliver packets immediately (no batching) — critical for real-time analysis
- **Promiscuous mode:** See all traffic on the network segment

### 11.4 Privilege Requirements

| Platform | Requirement |
|----------|-------------|
| macOS | Root access or `/dev/bpf*` group permissions |
| Windows | Npcap installed; may need admin elevation |
| Linux | `CAP_NET_RAW` capability or root |

### 11.5 High-Performance Techniques

| Technique | Description | Platform |
|-----------|-------------|----------|
| BPF kernel filters | Filter in kernel before copy to userspace | All (via libpcap) |
| PACKET_MMAP/TPACKET_V3 | Zero-copy ring buffer | Linux only |
| Buffer size tuning | Increase kernel buffer | All |
| Immediate mode | Low-latency delivery | All |
| Interrupt coalescing | Batch NIC interrupts | Linux (driver-level) |

### 11.6 BACnet Traffic Volume Context

BACnet/IP traffic is typically **low to moderate volume** (building automation, not datacenter traffic):
- Standard libpcap with a BPF filter is sufficient for most deployments
- Large campus: 200–1000+ devices, ~2000+ packets/sec peak
- BPF filter `udp port 47808` dramatically reduces the packet stream at kernel level

---

## 12. BACpypes3 Reference Architecture

### 12.1 Repositories

| Repository | Python | Status |
|---|---|---|
| JoelBender/bacpypes | 2.5/2.7/3.4+ | Legacy (last release v0.18.6, Feb 2022) |
| JoelBender/BACpypes3 | 3.8+ | **Active** (async/await, asyncio-based) |

### 12.2 Key Modules

| Module | Purpose |
|--------|---------|
| `bvll.py` | BVLC encode/decode — `BVLCI`, `BVLPDU`, all 12 function type classes |
| `npdu.py` | NPDU encode/decode — `NPCI`, `NPDU`, all network message classes |
| `apdu.py` | APDU encode/decode — all PDU types, service request/response classes |
| `pdu.py` | Base PDU with `Address` class (6 address types), `pack_ip_addr`, `unpack_ip_addr` |
| `comm.py` | Base communication framework — `PCI`, `PDUData`, `Client/Server`, `SAP/ASE` |
| `object.py` | BACnet object model — `Property`, `Object`, all standard object types |
| `analysis.py` | **Pcap decode pipeline** — `decode_packet()`, `decode_file()`, `Tracer` |

### 12.3 analysis.py — Key Module for Monitoring

This module provides a complete pcap-to-BACnet decoding pipeline:

| Function | Purpose |
|----------|---------|
| `decode_ethernet(s)` | Parse Ethernet frame |
| `decode_ip(s)` | Parse IP header |
| `decode_udp(s)` | Parse UDP header |
| **`decode_packet(data)`** | **Full pipeline: Ethernet → IP → UDP → BVLC → NPDU → APDU** |
| `decode_file(fname)` | Open pcap file, yield decoded packets with timestamp |
| `trace(fname, tracers)` | Run decoded packets through `Tracer` state machines |

### 12.4 Decode Pipeline Flow

1. Check for `0x81` byte → decode as `BVLPDU`
2. Look up specific BVLC type via `bvl_pdu_types[function_code]`
3. For `ForwardedNPDU`, extract originating address from BVLC
4. Check NPDU version == `0x01` → decode as `NPDU`
5. If `npduNetMessage is None` → application message → decode as `APDU`
6. Look up APDU type, then service-specific class
7. If network message → decode via `npdu_types`

### 12.5 Registration Pattern

```python
# Each class has a messageType and is registered:
register_bvlpdu_type() → bvl_pdu_types dict
register_npdu_type()   → npdu_types dict
register_apdu_type()   → apdu_types dict
```

### 12.6 BVLC Classes (from bvll.py)

| Class | BVLC Function | Code |
|-------|--------------|------|
| `BVLCI` | Base class for BVLC header encode/decode | — |
| `BVLPDU` | Full BVLC PDU with data | — |
| `Result` | BVLC Result message | 0x00 |
| `WriteBroadcastDistributionTable` | Write BDT | 0x01 |
| `ReadBroadcastDistributionTable` | Read BDT | 0x02 |
| `ReadBroadcastDistributionTableAck` | Read BDT ACK | 0x03 |
| `ForwardedNPDU` | Forwarded NPDU (carries originating IP) | 0x04 |
| `RegisterForeignDevice` | Register Foreign Device (carries TTL) | 0x05 |
| `ReadForeignDeviceTable` | Read FDT | 0x06 |
| `ReadForeignDeviceTableAck` | Read FDT ACK | 0x07 |
| `DeleteForeignDeviceTableEntry` | Delete FDT Entry | 0x08 |
| `DistributeBroadcastToNetwork` | Distribute Broadcast | 0x09 |
| `OriginalUnicastNPDU` | Original Unicast | 0x0A |
| `OriginalBroadcastNPDU` | Original Broadcast | 0x0B |

### 12.7 NPDU Classes (from npdu.py)

| Class | Message Type Code |
|-------|------------------|
| `NPCI` | Base class for NPCI header |
| `NPDU` | Full NPDU = NPCI + PDUData |
| `WhoIsRouterToNetwork` | 0x00 |
| `IAmRouterToNetwork` | 0x01 |
| `ICouldBeRouterToNetwork` | 0x02 |
| `RejectMessageToNetwork` | 0x03 |
| `RouterBusyToNetwork` | 0x04 |
| `RouterAvailableToNetwork` | 0x05 |
| `InitializeRoutingTable` | 0x06 |
| `InitializeRoutingTableAck` | 0x07 |
| `EstablishConnectionToNetwork` | 0x08 |
| `DisconnectConnectionToNetwork` | 0x09 |
| `WhatIsNetworkNumber` | 0x12 |
| `NetworkNumberIs` | 0x13 |

### 12.8 APDU Classes (from apdu.py)

| Class | PDU Type |
|-------|----------|
| `ConfirmedRequestPDU` | 0 |
| `UnconfirmedRequestPDU` | 1 |
| `SimpleAckPDU` | 2 |
| `ComplexAckPDU` | 3 |
| `SegmentAckPDU` | 4 |
| `ErrorPDU` | 5 |
| `RejectPDU` | 6 |
| `AbortPDU` | 7 |

### 12.9 PDU Base Classes (from pdu.py)

| Class | Purpose |
|-------|---------|
| `Address` | BACnet address parsing (6 address types) |
| `LocalStation` | Local station address |
| `RemoteStation` | Address on a remote network (net, addr) |
| `LocalBroadcast` | Local broadcast (`*`) |
| `RemoteBroadcast` | Broadcast on a remote network (`net:*`) |
| `GlobalBroadcast` | Global broadcast (`*:*`) |
| `pack_ip_addr(addr_tuple)` | `('1.2.3.4', 47808)` → 6-byte BACnet address |
| `unpack_ip_addr(bytes6)` | 6-byte BACnet address → `('1.2.3.4', 47808)` |

---

## 13. Scapy Packet Capture

### 13.1 AsyncSniffer — Recommended for Real-Time Capture

```python
from scapy.all import AsyncSniffer

sniffer = AsyncSniffer(
    iface="en0",
    filter="udp port 47808",
    prn=process_packet,
    store=False,  # Critical for high-volume — don't store in memory
)
sniffer.start()
# ... app runs ...
results = sniffer.stop()
```

### 13.2 Key Parameters

| Parameter | Description |
|-----------|-------------|
| `filter` | BPF filter string (kernel-level, critical for performance) |
| `store` | Set to `False` for high-volume to avoid memory issues |
| `prn` | Callback per packet |
| `lfilter` | Python-level filter (slower than BPF) |
| `stop_filter` | Condition to stop capture |
| `started_callback` | Notified when sniffer is ready |

### 13.3 BACnet Support in Scapy

**Scapy does NOT have a built-in BACnet layer.** A custom dissector or BACpypes3 is needed for protocol parsing.

### 13.4 Integration Pattern: Scapy + BACpypes3

- Use **Scapy** for passive packet capture (all BACnet traffic on the wire)
- Use **BACpypes3** for protocol decoding (BVLC → NPDU → APDU parsing)
- Bridge via `asyncio.Queue`: Scapy sniffer thread → queue → async analysis

```python
import asyncio
from scapy.all import AsyncSniffer, UDP

class BACnetMonitor:
    def __init__(self):
        self.sniffer = None
        self.packet_queue = asyncio.Queue(maxsize=10000)

    async def start_passive_capture(self, interface: str):
        """Scapy: capture ALL BACnet traffic on the network"""
        self.sniffer = AsyncSniffer(
            iface=interface,
            filter="udp port 47808",
            prn=self._on_packet,
            store=False,
        )
        self.sniffer.start()

    def _on_packet(self, pkt):
        """Process captured packet — extract raw bytes and queue"""
        if UDP in pkt:
            raw = bytes(pkt[UDP].payload)
            try:
                self.packet_queue.put_nowait({
                    'timestamp': float(pkt.time),
                    'src_ip': pkt[IP].src,
                    'dst_ip': pkt[IP].dst,
                    'raw': raw,
                    'length': len(pkt),
                })
            except asyncio.QueueFull:
                pass  # Drop on overflow
```

### 13.5 Performance at ~2000 pps

- With BPF filter + minimal dissection: Scapy handles 2000 pps on modern hardware
- `store=False` is critical to prevent memory growth
- Minimize work in `prn` callback — queue raw data, process in separate thread/task
- BPF filter `udp port 47808` dramatically reduces the packet stream at kernel level

---

## 14. Desktop App Architecture: Electron + Python

### 14.1 Architecture Overview

```
┌──────────────────────────────────────────┐
│            Electron Shell                │
│  ┌──────────────────────────────────┐    │
│  │     React Frontend (Renderer)    │    │
│  │   ┌───────────┐ ┌────────────┐   │    │
│  │   │  REST API  │ │ WebSocket  │   │    │
│  │   └─────┬─────┘ └─────┬──────┘   │    │
│  └─────────┼──────────────┼──────────┘    │
│            │              │               │
│  ┌─────────┼──────────────┼──────────┐    │
│  │   Main Process (Node.js)          │    │
│  │   - child_process.spawn(python)   │    │
│  │   - process lifecycle mgmt        │    │
│  │   - native OS integration         │    │
│  └─────────┼──────────────┼──────────┘    │
└────────────┼──────────────┼───────────────┘
             │              │
     ┌───────┴──────────────┴───────────┐
     │   Python FastAPI (localhost:8765) │
     │   ┌────────────┐ ┌────────────┐  │
     │   │  Scapy     │ │  BACpypes3 │  │
     │   │  Capture   │ │  Protocol  │  │
     │   └────────────┘ └────────────┘  │
     └──────────────────────────────────┘
```

### 14.2 Process Communication

- **HTTP REST** for request/response operations (device list, stats, capture control)
- **WebSocket** for real-time streaming (live packets, stats updates, anomaly alerts)
- Both on `127.0.0.1:8765`

### 14.3 Python Process Management (Electron main.ts)

```typescript
// Spawn Python backend
const pythonProcess = spawn(getPythonPath(), getArgs(), {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, PYTHONUNBUFFERED: '1' },
});

// Health check polling
async function waitForBackend(maxRetries = 30, delay = 500): Promise<boolean> {
    for (let i = 0; i < maxRetries; i++) {
        try {
            const response = await fetch(`http://127.0.0.1:8765/api/health`);
            if (response.ok) return true;
        } catch { /* Not ready yet */ }
        await new Promise((r) => setTimeout(r, delay));
    }
    return false;
}

// Kill on app close
app.on('before-quit', () => {
    if (process.platform !== 'win32') {
        process.kill(-pythonProcess.pid!, 'SIGTERM');
    } else {
        spawn('taskkill', ['/pid', String(pythonProcess.pid), '/f', '/t']);
    }
});
```

### 14.4 Python Bundling

- **PyInstaller** with `--onedir` mode bundles Python + all dependencies + interpreter
- Hidden imports needed for uvicorn, scapy submodules
- Build separately on each target OS (not cross-compilable)

### 14.5 Electron Packaging

- **electron-builder** for `.dmg`/`.pkg` (macOS) and NSIS `.exe` (Windows)
- PyInstaller output bundled via `extraResources`
- CI/CD with GitHub Actions (macOS + Windows runners)

### 14.6 Privilege Escalation

| Platform | Strategy |
|----------|----------|
| macOS | `osascript` AppleScript admin dialog, or `.pkg` post-install BPF permissions |
| Windows | Require Npcap; optional admin elevation via PowerShell `Start-Process -Verb RunAs` |

### 14.7 Reference Projects

| Project | Stars | Notes |
|---------|-------|-------|
| every-pdf | 1,085 | Best reference — Nextron + FastAPI + PyInstaller |
| SpotifyElectron | 81 | Electron + React + Python backend |
| react-vite-electron-fastapi-template | 18 | Clean starter template |

---

## 15. Performance Considerations

### 15.1 Pipeline Architecture

```
Scapy Capture Thread   →   asyncio.Queue   →   Parser/Analysis   →   WebSocket Broadcast
(dedicated thread)          (thread-safe)       (async tasks)          (to React UI)
```

### 15.2 Key Optimizations

1. **BPF filter** at kernel level — only BACnet packets reach Python
2. **`store=False`** in Scapy — no memory accumulation
3. **Queue with maxsize** — backpressure handling (drop oldest on overflow)
4. **Batch WebSocket updates** — aggregate stats, send at 1Hz not per-packet
5. **Sliding window stats** — 1s, 10s, 60s windows for rate calculations
6. **Separate concerns** — capture thread, parse task, analysis task, WebSocket task

---

## 16. Data Link / Physical Layers

| Layer | Type Code | Description |
|-------|-----------|-------------|
| BACnet/IP (BIP) | 5 | UDP/IP on port 47808 |
| BACnet/IPv6 (BIP6) | 9 | IPv6 |
| Ethernet | 0 | Direct Ethernet MAC |
| ARCNET | 1 | Token bus |
| **MS/TP** | **2** | **RS-485 token passing (future expansion target)** |
| PTP | 3 | Point-to-point RS-232 |
| LonTalk | 4 | Echelon proprietary |
| ZigBee | 6 | Wireless |
| Virtual | 7 | — |
| BACnet/SC | 11 | Secure Connect (WebSocket/TLS) |

### 16.1 MS/TP (Future Expansion)

BACnet MS/TP uses RS-485 serial:
- Token-passing protocol on a shared bus
- Master nodes pass token; slave nodes respond when polled
- Frame types: Token, Poll-For-Master, Reply-To-Poll-For-Master, Test-Request, Test-Response, Data-Expecting-Reply, Data-Not-Expecting-Reply
- The transport abstraction layer (`TransportCapture` base class) in the architecture enables adding MS/TP support without restructuring the analysis or UI pipeline

---

## Sources

- **BACpypes3 GitHub:** github.com/JoelBender/BACpypes3 (active, async Python BACnet stack)
- **BACpypes GitHub:** github.com/JoelBender/bacpypes (legacy, comprehensive reference)
- **ANSI/ASHRAE Standard 135:** Definitive BACnet specification (copyrighted)
- **Wireshark BACnet dissectors:** packet-bvlc.c, packet-bacnet.c, packet-bacapp.c
- **Scapy documentation:** scapy.readthedocs.io
- **Electron documentation:** electronjs.org
- **libpcap/Npcap documentation:** tcpdump.org, npcap.com
