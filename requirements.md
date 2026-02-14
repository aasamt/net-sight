# NetSight — Requirements Document

**Application Name:** NetSight
**Purpose:** Desktop application for monitoring, analyzing, and quantifying BACnet/IP network traffic
**Target Users:** Controls, HVAC, BMS, and building automation technicians/engineers
**Version:** 1.0 (Capture & Analysis MVP)

---

## 1. Product Overview

NetSight is a cross-platform desktop application that passively captures BACnet/IP network traffic, parses it at all protocol layers (BVLC, NPDU, APDU), and provides real-time analysis including device discovery, traffic statistics, service breakdowns, and anomaly detection. The tool helps building automation professionals understand BACnet network health, identify communicating devices, quantify traffic patterns, and diagnose issues.

---

## 2. Target Platforms

| Platform | Minimum Version |
|----------|----------------|
| macOS | macOS 12 (Monterey) or later, Intel & Apple Silicon |
| Windows | Windows 10 (64-bit) or later |

---

## 3. Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Desktop Shell | Electron | Latest stable |
| Frontend | React + TypeScript (Vite) | React 18+, TS 5+ |
| Backend | Python + FastAPI + Uvicorn | Python 3.12+ |
| Packet Capture | Scapy (AsyncSniffer) | Latest stable |
| BACnet Parsing | BACpypes3 | Latest stable |
| IPC | HTTP REST + WebSocket (localhost:8765) | — |
| Python Bundling | PyInstaller (--onedir) | Latest stable |
| App Packaging | electron-builder | Latest stable |

---

## 4. Functional Requirements

### 4.1 Packet Capture

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-CAP-01 | Capture live BACnet/IP traffic on a user-selected network interface | P0 |
| FR-CAP-02 | Filter capture at kernel level using BPF filter `udp port 47808` | P0 |
| FR-CAP-03 | List available network interfaces for user selection | P0 |
| FR-CAP-04 | Start and stop capture via UI controls | P0 |
| FR-CAP-05 | Import pcap files captured by external tools (Wireshark, tcpdump) | P0 |
| FR-CAP-06 | Save current capture session to pcap file | P0 |
| FR-CAP-07 | Display capture status (running/stopped, duration, packet count) | P0 |
| FR-CAP-08 | Handle privilege escalation for live capture (macOS: admin prompt; Windows: Npcap + optional admin) | P0 |
| FR-CAP-09 | Capture on a single network interface at a time | P0 |
| FR-CAP-10 | Reload/replay saved pcap sessions for re-analysis | P1 |

### 4.2 BACnet Protocol Parsing

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-PAR-01 | Parse BVLC layer: type (0x81), function code, length; all 12 function types | P0 |
| FR-PAR-02 | Parse NPDU layer: version, control flags, DNET/DADR, SNET/SADR, hop count, network priority | P0 |
| FR-PAR-03 | Parse NPDU network layer messages (Who-Is-Router, I-Am-Router, Reject-Message, etc.) | P0 |
| FR-PAR-04 | Parse APDU layer: PDU type (all 8 types), service choice, invoke ID | P0 |
| FR-PAR-05 | Map confirmed service choices to names (ReadProperty, WriteProperty, SubscribeCOV, etc.) | P0 |
| FR-PAR-06 | Map unconfirmed service choices to names (Who-Is, I-Am, COV Notification, etc.) | P0 |
| FR-PAR-07 | Handle Forwarded-NPDU — extract originating device IP from BVLC | P0 |
| FR-PAR-08 | Parse APDU service data for deep inspection (object identifiers, property IDs, values) | P1 |
| FR-PAR-09 | Handle segmented messages (detect segmentation, track segment sequences) | P1 |
| FR-PAR-10 | Parse Error, Reject, and Abort PDUs with reason codes | P0 |
| FR-PAR-11 | Decode BACnet object identifiers (object type + instance number from 32-bit value) | P0 |

### 4.3 Device Discovery & Registry

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-DEV-01 | Automatically discover devices from I-Am responses (device instance, vendor ID, IP address) | P0 |
| FR-DEV-02 | Track device first-seen and last-seen timestamps | P0 |
| FR-DEV-03 | Track per-device packet count and byte count | P0 |
| FR-DEV-04 | Track per-device traffic rate (packets/sec) | P0 |
| FR-DEV-05 | Identify device source from IP address for all packet types (not just I-Am) | P0 |
| FR-DEV-06 | Display device list with sortable/filterable columns | P0 |
| FR-DEV-07 | Correlate device instance numbers with IP addresses across BVLC forwarding | P1 |

### 4.4 Traffic Statistics

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-STA-01 | Compute global statistics: total packets, total bytes, capture duration | P0 |
| FR-STA-02 | Compute real-time rates: packets/sec, bytes/sec (1s, 10s, 60s sliding windows) | P0 |
| FR-STA-03 | Compute per-device statistics: packet count, byte count, rate, % of total | P0 |
| FR-STA-04 | Compute per-service breakdown: count of each BACnet service type | P0 |
| FR-STA-05 | Compute per-BVLC-function breakdown: count of each BVLC function type | P0 |
| FR-STA-06 | Compute per-priority-level breakdown | P1 |
| FR-STA-07 | Identify top talkers (devices generating the most traffic) | P0 |
| FR-STA-08 | Track confirmed vs unconfirmed request ratio | P1 |
| FR-STA-09 | Track error/reject/abort rates globally and per-device | P0 |

### 4.5 Anomaly Detection

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-ANO-01 | Detect chatty devices exceeding configurable packets/sec threshold | P0 |
| FR-ANO-02 | Detect broadcast storms (excessive Who-Is or I-Am traffic) | P0 |
| FR-ANO-03 | Detect high error/reject/abort rates per device | P0 |
| FR-ANO-04 | Detect network congestion (overall traffic rate exceeding threshold) | P1 |
| FR-ANO-05 | Detect routing issues (Reject-Message-To-Network occurrences) | P1 |
| FR-ANO-06 | Detect foreign device registration failures (BVLC NAKs) | P1 |
| FR-ANO-07 | Allow user-configurable thresholds for anomaly detection | P1 |
| FR-ANO-08 | Display anomalies with severity level, device, description, timestamp | P0 |

### 4.6 Packet Inspection

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-INS-01 | Display packet list with columns: #, Timestamp, Source, Destination, BVLC Function, Service, Length | P0 |
| FR-INS-02 | Click packet to view full decoded detail (all layers: BVLC, NPDU, APDU) | P0 |
| FR-INS-03 | Display raw hex dump of packet bytes | P1 |
| FR-INS-04 | Filter packet list by service type, source/destination, device instance | P1 |
| FR-INS-05 | Configurable detail level: summary, normal, full decode | P1 |
| FR-INS-06 | Auto-scroll during live capture with ability to pause scrolling | P0 |

### 4.7 Export

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-EXP-01 | Export captured packets as pcap file | P0 |
| FR-EXP-02 | Export device list as CSV | P0 |
| FR-EXP-03 | Export device list as JSON | P0 |
| FR-EXP-04 | Export traffic statistics as CSV | P1 |
| FR-EXP-05 | Export traffic statistics as JSON | P1 |
| FR-EXP-06 | Export full analysis report as JSON | P1 |

### 4.8 Session Management

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-SES-01 | Save capture sessions (pcap + metadata: start time, interface, duration, device count) | P0 |
| FR-SES-02 | Load previously saved capture sessions for re-analysis | P0 |
| FR-SES-03 | Display session metadata in the UI | P1 |

---

## 5. Non-Functional Requirements

### 5.1 Performance

| ID | Requirement |
|----|-------------|
| NFR-PER-01 | Handle sustained capture at 2000+ packets/sec without packet loss |
| NFR-PER-02 | Parse and analyze packets in real-time during live capture |
| NFR-PER-03 | WebSocket updates to frontend at ≤1 second latency |
| NFR-PER-04 | Stats aggregation pushed to UI at 1Hz (once per second) |
| NFR-PER-05 | Packet list UI must use virtualized scrolling for 100,000+ packets |
| NFR-PER-06 | In-memory analysis should not exceed 2GB RAM for typical sessions |

### 5.2 Reliability

| ID | Requirement |
|----|-------------|
| NFR-REL-01 | Graceful handling of malformed/truncated BACnet packets (log & skip, don't crash) |
| NFR-REL-02 | Graceful Python backend shutdown on app close (SIGTERM/taskkill) |
| NFR-REL-03 | Auto-restart Python backend if it crashes unexpectedly |
| NFR-REL-04 | Queue backpressure handling — drop oldest packets when queue is full rather than blocking capture |

### 5.3 Security

| ID | Requirement |
|----|-------------|
| NFR-SEC-01 | Python backend only listens on `127.0.0.1` (localhost) — no external access |
| NFR-SEC-02 | Privilege escalation only when user initiates live capture |
| NFR-SEC-03 | No persistent admin/root access — elevate only for capture start |

### 5.4 Usability

| ID | Requirement |
|----|-------------|
| NFR-USA-01 | Clear guidance when Npcap is not installed (Windows) |
| NFR-USA-02 | Clear guidance when admin/root privileges are needed |
| NFR-USA-03 | Responsive UI — capture controls and status visible at all times |
| NFR-USA-04 | BACnet service names displayed in human-readable format (not raw codes) |

### 5.5 Maintainability

| ID | Requirement |
|----|-------------|
| NFR-MAI-01 | Transport abstraction layer: `TransportCapture` base class with `start()`, `stop()`, `list_interfaces()`, `on_packet()` |
| NFR-MAI-02 | BACnet/IP capture implemented as `BACnetIPCapture(TransportCapture)` |
| NFR-MAI-03 | Pcap replay implemented as `PcapReplayCapture(TransportCapture)` |
| NFR-MAI-04 | Architecture must support adding BACnet MS/TP (RS-485) transport without restructuring analysis or UI |
| NFR-MAI-05 | Parser modules separated by layer: `bvlc.py`, `npdu.py`, `apdu.py`, `pipeline.py` |
| NFR-MAI-06 | Analysis modules separated by concern: `device_registry.py`, `traffic_stats.py`, `anomaly_detector.py` |

---

## 6. Architecture

### 6.1 High-Level Components

```
┌──────────────────────────────────────────┐
│            Electron Shell                │
│  ┌──────────────────────────────────┐    │
│  │     React Frontend (Renderer)    │    │
│  │     - Capture controls           │    │
│  │     - Packet table               │    │
│  │     - Device list                │    │
│  │     - Stats dashboard            │    │
│  │     - Anomaly alerts             │    │
│  └──────────────────────────────────┘    │
│                                          │
│  ┌──────────────────────────────────┐    │
│  │   Main Process (Node.js/TS)      │    │
│  │   - Spawn/manage Python backend  │    │
│  │   - Health check polling         │    │
│  │   - Native OS integration        │    │
│  │   - File dialogs                 │    │
│  └──────────────────────────────────┘    │
└──────────────────────────────────────────┘
                    │
        HTTP REST + WebSocket
          (localhost:8765)
                    │
┌──────────────────────────────────────────┐
│   Python FastAPI Backend                 │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │  Transport Layer                   │  │
│  │  ┌──────────────┐ ┌─────────────┐ │  │
│  │  │ BACnetIP     │ │ PcapReplay  │ │  │
│  │  │ Capture      │ │ Capture     │ │  │
│  │  └──────────────┘ └─────────────┘ │  │
│  │  (Future: MS/TP Capture)          │  │
│  └────────────────────────────────────┘  │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │  Parser Pipeline                   │  │
│  │  BVLC → NPDU → APDU              │  │
│  │  (BACpypes3 decode_packet)        │  │
│  └────────────────────────────────────┘  │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │  Analysis Engine                   │  │
│  │  ┌──────────┐ ┌────────────────┐  │  │
│  │  │ Device   │ │ Traffic Stats  │  │  │
│  │  │ Registry │ │ (sliding win)  │  │  │
│  │  └──────────┘ └────────────────┘  │  │
│  │  ┌──────────┐ ┌────────────────┐  │  │
│  │  │ Anomaly  │ │ Packet         │  │  │
│  │  │ Detector │ │ Inspector      │  │  │
│  │  └──────────┘ └────────────────┘  │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

### 6.2 Data Flow Pipeline

```
Scapy AsyncSniffer (capture thread)
         │
         ▼
    asyncio.Queue (thread-safe bridge, maxsize=10000)
         │
         ▼
    Parser Pipeline (BVLC → NPDU → APDU)
         │
         ├──▶ Device Registry (accumulate)
         ├──▶ Traffic Stats (aggregate)
         ├──▶ Anomaly Detector (evaluate)
         ├──▶ In-Memory Packet Store
         │
         ▼
    WebSocket Broadcast
    ├── /ws/packets  (real-time packet stream)
    ├── /ws/stats    (1Hz stats updates)
    └── /ws/anomalies (real-time alerts)
```

### 6.3 Project Structure

```
bacnet_monitor/
├── backend/
│   ├── main.py                    # FastAPI entry point (uvicorn)
│   ├── pyproject.toml             # Python dependencies
│   ├── transport/
│   │   ├── __init__.py
│   │   ├── base.py                # TransportCapture abstract base
│   │   ├── bacnet_ip.py           # BACnetIPCapture (Scapy AsyncSniffer)
│   │   └── pcap_replay.py         # PcapReplayCapture (pcap file import)
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── bvlc.py                # BVLC layer parser
│   │   ├── npdu.py                # NPDU layer parser
│   │   ├── apdu.py                # APDU layer parser
│   │   └── pipeline.py            # Full decode pipeline orchestration
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── device_registry.py     # Live device tracking
│   │   ├── traffic_stats.py       # Real-time statistics
│   │   ├── anomaly_detector.py    # Issue detection
│   │   └── packet_inspector.py    # Deep packet inspection
│   ├── api/
│   │   ├── __init__.py
│   │   ├── capture.py             # Capture control endpoints
│   │   ├── analysis.py            # Analysis data endpoints
│   │   ├── export.py              # Export endpoints
│   │   └── ws.py                  # WebSocket endpoints
│   └── tests/
│       ├── test_parsers.py        # Parser unit tests
│       ├── test_analysis.py       # Analysis unit tests
│       └── fixtures/              # Test pcap files
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   └── src/
│       ├── App.tsx
│       ├── services/
│       │   └── api.ts             # REST + WebSocket client
│       ├── pages/
│       │   └── CapturePage.tsx     # Main capture page
│       └── components/
│           ├── PacketTable.tsx     # Virtualized packet list
│           ├── DeviceList.tsx      # Device registry table
│           ├── StatsPanel.tsx      # Statistics dashboard
│           └── AnomalyPanel.tsx    # Anomaly alerts
├── electron/
│   ├── main.ts                    # Electron main process
│   ├── preload.ts                 # IPC bridge
│   └── electron-builder.yml       # Packaging config
├── research.md
├── requirements.md
└── README.md
```

---

## 7. API Specification

### 7.1 REST Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check (used by Electron to confirm backend is ready) |
| GET | `/api/interfaces` | List available network interfaces |
| POST | `/api/capture/start` | Start live capture on specified interface |
| POST | `/api/capture/stop` | Stop active capture |
| GET | `/api/capture/status` | Current capture state, duration, packet count |
| POST | `/api/capture/import` | Import a pcap file for analysis |
| POST | `/api/capture/save` | Save current capture to pcap file |
| GET | `/api/devices` | Device registry (all discovered devices) |
| GET | `/api/stats` | Current traffic statistics |
| GET | `/api/anomalies` | Detected anomalies/issues |
| GET | `/api/packets?offset=N&limit=M&filter=...` | Paginated packet list |
| GET | `/api/packets/{id}` | Full decoded detail of a single packet |
| GET | `/api/export/pcap` | Download capture as pcap file |
| GET | `/api/export/devices?format=csv\|json` | Export device list |
| GET | `/api/export/stats?format=csv\|json` | Export statistics |
| GET | `/api/export/report?format=json` | Full analysis report |

### 7.2 WebSocket Endpoints

| Path | Description | Update Frequency |
|------|-------------|-----------------|
| `WS /ws/packets` | Real-time parsed packet stream | Per-packet |
| `WS /ws/stats` | Aggregated statistics | 1Hz (every 1 second) |
| `WS /ws/anomalies` | Real-time anomaly alerts | On detection |

---

## 8. Dependencies

### 8.1 Python Backend

| Package | Purpose |
|---------|---------|
| `fastapi` | REST API + WebSocket framework |
| `uvicorn[standard]` | ASGI server |
| `scapy` | Packet capture (AsyncSniffer) |
| `bacpypes3` | BACnet protocol parsing |
| `pydantic` | Data models and validation |
| `websockets` | WebSocket support for FastAPI |

### 8.2 Frontend

| Package | Purpose |
|---------|---------|
| `react` | UI framework |
| `react-dom` | DOM rendering |
| `typescript` | Type safety |
| `vite` | Build tool |
| (charting lib TBD) | Visualization (Phase 2) |
| (virtual list lib TBD) | Packet table virtualization |

### 8.3 Electron

| Package | Purpose |
|---------|---------|
| `electron` | Desktop shell |
| `electron-builder` | Packaging and distribution |

### 8.4 Platform Prerequisites

| Platform | Prerequisite |
|----------|-------------|
| macOS | Admin privileges for `/dev/bpf*` access |
| Windows | Npcap driver installed |

---

## 9. Extensibility Requirements

### 9.1 Future: BACnet MS/TP (RS-485) Support

The architecture must support adding RS-485 serial capture without restructuring:
- New `MSTBCapture(TransportCapture)` class in `transport/`
- MS/TP frame parsing in `parsers/` (token, data-expecting-reply, data-not-expecting-reply frames)
- Same analysis pipeline (device registry, stats, anomalies) works with MS/TP data
- UI shows transport type but uses the same views

### 9.2 Future: Visualization Phase

- Charts, graphs, network topology diagrams
- Time-series traffic analysis
- Device communication pattern visualization
- Export to PDF reports

---

## 10. Testing Requirements

| ID | Requirement |
|----|-------------|
| TEST-01 | Unit tests for each parser layer (BVLC, NPDU, APDU) using known packet hex samples |
| TEST-02 | Unit tests for device registry accumulation logic |
| TEST-03 | Unit tests for traffic statistics calculations |
| TEST-04 | Unit tests for anomaly detection thresholds |
| TEST-05 | Integration test: import pcap → verify devices, services, anomalies |
| TEST-06 | Performance test: 2000+ pps sustained for 5 minutes without drops |
| TEST-07 | Edge case tests: malformed packets, truncated data, zero-length APDUs |
| TEST-08 | Cross-platform build verification (macOS + Windows) |
| TEST-09 | Test pcap file with representative BACnet traffic for all test scenarios |

---

## 11. Decisions Log

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Desktop framework | Electron + Python backend | User prefers Python; Electron provides native desktop shell |
| Frontend framework | React + TypeScript (Vite) | Most popular, huge ecosystem for charts/tables |
| Backend framework | FastAPI + WebSocket | Async, fast, modern Python; native WebSocket support |
| Packet capture | Scapy (AsyncSniffer) | Most versatile; BPF filter at kernel level handles BACnet scale |
| BACnet parsing | BACpypes3 | Active, async, proven decode_packet() pipeline |
| Data persistence | Pcap files + in-memory analysis | Industry standard, shareable with Wireshark |
| Transport architecture | Abstract base class | Enables future MS/TP support without restructuring |
| Capture mode | Live capture + pcap import | Maximum flexibility |
| Export formats | Pcap + CSV/JSON reports | Both raw data and analysis results |
| Interface support | Single interface | Sufficient for MVP; multi-interface is future |
| Python version | 3.12+ | Latest stable, best async performance |
| App name | NetSight | User-selected |
