# NetSight — Session Progress & Handoff

> **Last Updated:** February 19, 2026
> **Status:** Phase 5h Complete — TUI Settings Tab (194 tests passing)

---

## Instructions for AI Assistant

You are building a desktop app called NetSight — a BACnet/IP network traffic analyzer for building automation engineers. Before we continue, read this document and the following project files to understand the full context:

1. `research.md` — Deep technical research on BACnet/IP protocol (BVLC, NPDU, APDU layers), packet capture technologies, BACpypes3 architecture, Scapy integration, and Electron+Python desktop app patterns.
2. `requirements.md` — Full requirements document: functional/non-functional requirements with IDs (FR-xxx, NFR-xxx), API specification, project structure, tech stack, dependencies, and decisions log.
3. `session_progress.md` — This file. Contains implementation progress, completed items, remaining to-dos, and design decisions made during implementation.

After reading these files, tell me what has been completed and what the next implementation steps are based on the to-do checklist in session_progress.md.


---

## Project Summary

**NetSight** is a cross-platform desktop app (macOS + Windows) for monitoring, analyzing, and quantifying BACnet/IP network traffic.

| Aspect | Detail |
|--------|--------|
| **Stack** | Electron (shell) + React/TypeScript/Vite (frontend) + Python 3.12+/FastAPI (backend) |
| **Package Mgr** | uv (https://docs.astral.sh/uv/) — `uv sync`, `uv run` |
| **Capture** | Scapy AsyncSniffer with BPF filter `udp port 47808` |
| **Parsing** | BACpypes3 for BVLC → NPDU → APDU decode pipeline |
| **IPC** | HTTP REST + WebSocket on `127.0.0.1:8765` |
| **Bundling** | PyInstaller (Python), electron-builder (app) |
| **Persistence** | Pcap files + in-memory analysis |

---

## Implementation Progress

### Phase 1: Python Project Scaffolding
- [x] Initialize monorepo root with README.md
- [x] Set up `backend/` Python project with `pyproject.toml` (deps: fastapi, uvicorn, scapy, bacpypes3, pydantic, websockets)
- [x] Create `backend/models/` with shared Pydantic models
- [x] Verify Python environment: install deps, confirm imports work

**Requirement coverage:** NFR-SEC-01 (partial)

---

### Phase 2: Transport Abstraction Layer
- [x] Create `backend/transport/__init__.py`
- [x] Create `backend/transport/base.py` — abstract `TransportCapture` base class
  - Methods: `start()`, `stop()`, `list_interfaces()`, `on_packet(callback)`, `is_running`
- [x] Create `backend/transport/bacnet_ip.py` — `BACnetIPCapture(TransportCapture)`
  - Scapy `AsyncSniffer`, BPF filter `udp port 47808`, `store=False`, immediate mode
  - Interface selection, privilege check
- [x] Create `backend/transport/pcap_replay.py` — `PcapReplayCapture(TransportCapture)`
  - Scapy `rdpcap()` / `PcapReader()` for pcap file import
  - Replay packets through same callback pipeline

**Requirement coverage:** FR-CAP-01, FR-CAP-02, FR-CAP-05, NFR-MAI-01, NFR-MAI-02, NFR-MAI-03, NFR-MAI-04

---

### Phase 3: BACnet Protocol Parser
- [x] Create `backend/parsers/__init__.py`
- [x] Create `backend/parsers/bvlc.py` — BVLC layer parser
  - Decode 4-byte header (type=0x81, function code, length)
  - Handle all 12 BVLC function types (0x00–0x0B)
  - Extract originating address from Forwarded-NPDU (0x04)
  - Return `BVLCMessage` Pydantic model
- [x] Create `backend/parsers/npdu.py` — NPDU layer parser
  - Decode version (0x01), control byte flags
  - Parse optional DNET/DADR, SNET/SADR, hop count
  - Handle all 20 network layer message types
  - Return `NPDUMessage` Pydantic model
- [x] Create `backend/parsers/apdu.py` — APDU layer parser
  - Decode PDU type (8 types), service choice, invoke ID
  - Map 34 confirmed services + 14 unconfirmed services to names
  - Parse Error/Reject/Abort with reason codes
  - Decode object identifiers (type + instance from 32-bit)
  - Return `APDUMessage` Pydantic model
- [x] Create `backend/parsers/pipeline.py` — full decode orchestration
  - Raw bytes → BVLC → NPDU → APDU
  - Manual byte-level parsing as primary decoder
  - Graceful degradation: partial results on malformed packets
  - Output unified `ParsedPacket` Pydantic model

**Requirement coverage:** FR-PAR-01 through FR-PAR-11

---

### Phase 4: Analysis Engine
- [x] Create `backend/analysis/__init__.py`
- [x] Create `backend/analysis/device_registry.py`
  - Accumulate devices from I-Am responses (instance, vendor, IP)
  - Track first-seen, last-seen timestamps
  - Track per-device packet count, byte count, rate
  - IP-to-device correlation for all packet types
- [x] Create `backend/analysis/traffic_stats.py`
  - Global stats: total packets, bytes, duration
  - Real-time rates: 1s, 10s, 60s sliding windows
  - Per-device stats: count, bytes, rate, % of total
  - Per-service breakdown
  - Per-BVLC-function breakdown
  - Per-priority breakdown
  - Top talkers identification
  - Confirmed vs unconfirmed ratio
  - Error/reject/abort rates
- [x] Create `backend/analysis/anomaly_detector.py`
  - Chatty device detection (configurable threshold)
  - Broadcast storm detection (Who-Is/I-Am flood)
  - Error/reject/abort rate monitoring
  - Routing issue detection (Reject-Message-To-Network)
  - Foreign device registration failure tracking
  - Duplicate device ID detection (same instance from multiple IPs)
  - Cooldown-based deduplication to avoid alert floods
- [x] Create `backend/analysis/packet_inspector.py`
  - Three detail levels: summary, normal, full
  - Human-readable multi-line inspection with all layer fields
  - Dict serialization for JSON/REST output
  - Object/property identifier display

**Requirement coverage:** FR-DEV-01 through FR-DEV-07, FR-STA-01 through FR-STA-09, FR-ANO-01 through FR-ANO-08, FR-INS-05

---

### Phase 5: CLI Entry Point
- [x] Create `backend/main.py` — CLI entry point
  - Default mode: live capture on selected interface, parsed packets + periodic stats printed to terminal
  - `--interface` / `-i` flag: select network interface (default: auto-detect or prompt)
  - `--file` / `-f` flag: import and replay a pcap file instead of live capture
  - `--stats-interval` flag: seconds between stats summary output (default: 10)
  - `--serve` flag: start FastAPI server on `127.0.0.1:8765` instead of terminal output (stub)
  - Signal handlers (SIGTERM, SIGINT) for graceful shutdown
- [x] Implement asyncio.Queue pipeline: capture thread → parser → analysis → terminal output
  - Thread-safe bridge via `loop.call_soon_threadsafe()`
  - Queue maxsize=10000 with backpressure (drop on overflow)
- [x] Terminal output formatter
  - Per-packet summary line: `#N  timestamp  src_ip → dst_ip  BVLC_function  service_name  length`
  - Periodic stats block: total packets, pps, device count, top talkers, anomalies detected
  - Final report on shutdown with full statistics, devices, services, and anomalies
- [x] JSONL save support: `--save` / `-o` flag to write parsed packets to JSONL file
- [x] Verify end-to-end: `uv run python -m backend.main -f capture.pcap` replays and analyzes saved traffic
- [x] Additional flags: `--list-interfaces`, `--version`, `--quiet`, `--verbose`, `--replay-speed`
- [x] Created `backend/__main__.py` for `uv run python -m backend.main` support
- [x] 35 CLI tests covering: argparse, output formatting, pipeline integration, run_capture, packet summary

**Requirement coverage:** FR-CAP-01 through FR-CAP-07, FR-CAP-09, FR-CAP-10, NFR-PER-01, NFR-PER-02, NFR-REL-01, NFR-REL-04

---

### Phase 5b: Textual TUI Dashboard
- [x] Add `textual>=0.40.0` dependency to pyproject.toml
- [x] Create `backend/tui/__init__.py`
- [x] Create `backend/tui/styles.tcss` — Textual CSS for panel layout, sizing, colors, borders
- [x] Create `backend/tui/widgets.py`
  - `PacketTable` — DataTable with configurable ring buffer (default 50 rows)
  - `StatsPanel` — Global traffic statistics (packets, bytes, rates, confirmed/unconfirmed)
  - `DevicePanel` — Discovered BACnet devices list (max 10 shown, compact right panel)
  - `TopTalkersPanel` — Top 5 source IPs by packet count
  - `AnomalyLog` — Scrolling anomaly alert log (bottom dock)
  - `DeviceListPanel` — Full device list DataTable (added in Phase 5d)
- [x] Create `backend/tui/app.py` — `NetSightApp(App)`
  - `compose()` layout: Header → status bar → TabbedContent(Traffic tab, Devices tab) → Footer
  - `on_mount()` wires transport → async queue → consumer task → analysis engines → UI panels
  - 1Hz `set_interval` for stats/devices/top talkers panel refresh
  - Event-driven packet table updates (per-packet)
  - Keyboard bindings: Q quit, P pause/resume, S save to JSONL
  - Pcap replay: watches for transport completion, marks "Replay complete"
  - Queue backpressure: drop on overflow (10,000 maxsize)
- [x] Refactor `backend/main.py`
  - TUI is now default output mode (both live capture and pcap replay)
  - `--plain` flag preserves original scrolling terminal output for scripting/piping/CI
  - `--tui-packets N` flag configures max recent packets in DataTable (default: 50)
  - `run_tui()` function creates transport + NetSightApp and calls `app.run()`
- [x] 30 TUI tests covering: CLI flags, widget init, app lifecycle, Textual Pilot headless tests, keyboard bindings, plain mode compatibility

**Requirement coverage:** NFR-USA-03, NFR-USA-04 (partial — terminal UI)

---

### Phase 5c: TUI Enhancements — Packet Detail, Filtering & Model Extensions
- [x] Add `PacketDetailPanel` widget with horizontal split layout
  - Left side: decoded APDU detail (PDU type, service, invoke ID, object, property, I-Am/Who-Is fields)
  - Right side: raw hex dump (no ASCII), BVLC summary, NPDU summary
  - Wired to `on_data_table_row_highlighted` for row selection → detail update
  - O(1) packet lookup via `_packets_by_id` dict keyed by row index
- [x] Add live filter input to `PacketTable`
  - `Input` widget docked at top of packet table section
  - Filters across all columns (source, destination, PDU type, service, object)
  - Stores all rows in `_all_rows` deque, rebuilds DataTable on filter change
  - `_matches_filter()` for case-insensitive substring matching
- [x] Replace BVLC column with PDU Type column
  - Shows human-readable PDU type name (e.g., "Confirmed-REQ", "Unconfirmed-REQ", "Complex-ACK")
- [x] Add Object column with friendly format
  - Displays object type + instance (e.g., "Device-201", "AnalogInput-1")
  - Falls back to raw identifier if type not mappable
- [x] Extend APDU models with richer decode fields
  - `property_identifier`, `property_name` — decoded from context tag [1] for ReadProperty/WriteProperty services
  - `property_array_index` — optional array index
  - `iam_fields: IAmFields` — device_instance, max_apdu_length, segmentation_supported/name, vendor_id
  - `who_is_range: WhoIsRange` — low_limit, high_limit
  - `service_data_hex` — raw hex of service-specific payload
  - `PROPERTY_IDENTIFIERS` dict (~30 common BACnet properties)
  - `SEGMENTATION_VALUES` dict for segmentation decode
- [x] Extend APDU parser with new extraction functions
  - `_try_extract_property_id()` — extracts property identifier from context tag [1] for services 12-16
  - `_try_extract_iam_fields()` — extracts 4 application-tagged values from I-Am responses
  - `_try_extract_whois_range()` — extracts context-tagged range limits from Who-Is requests
  - All confirmed/unconfirmed/complex-ACK parsers now store `service_data_hex`
- [x] Layout refinements
  - Bottom container: `PacketDetailPanel` (2fr left) + `AnomalyLog` (1fr right)
  - `AnomalyLog` now 100% height, shows 15 entries
  - Hex dump without ASCII column for cleaner display
  - `#detail-split` horizontal layout for decoded vs raw sections
  - `#packet-filter` styled as 1-line docked input

**Requirement coverage:** FR-INS-05 (packet detail), FR-PAR-01 through FR-PAR-11 (enriched parsing), NFR-USA-03, NFR-USA-04

---

### Phase 5d: TUI Tabbed Interface — Devices Tab
- [x] Refactor TUI layout to use Textual `TabbedContent` with `TabPane` widgets
  - **Traffic tab** — existing dashboard (packet table, stats, devices, top talkers, detail panel, anomaly log)
  - **Devices tab** — new full-screen `DeviceListPanel` with sortable DataTable
- [x] Add `DeviceListPanel` widget to `backend/tui/widgets.py`
  - DataTable columns: IP Address, Device ID, Object Type, Vendor ID, Packets, Bytes, First Seen, Last Seen
  - Known devices (from I-Am discovery) shown with full details, sorted by instance
  - Unknown IPs (seen in traffic but no I-Am) shown with "—" placeholders
  - Summary label showing total IPs, identified devices, unknown IPs counts
  - Refreshes at 1 Hz alongside other panels
- [x] Add helper methods to analysis engines
  - `DeviceRegistry.get_ip_to_instance()` — returns IP→device-instance mapping
  - `TrafficStats.get_all_source_ips()` — returns all unique source IPs seen in traffic
- [x] Add tab-related CSS styles to `backend/tui/styles.tcss`
  - `TabbedContent`, `TabPane`, `DeviceListPanel`, `#device-list-table`, `#device-list-summary`
- [x] Wire `DeviceListPanel` refresh into `_refresh_panels()` (1 Hz cycle)
- [x] All 160 existing tests pass — no regressions

**Requirement coverage:** FR-DEV-01 through FR-DEV-07 (device tracking/display), NFR-USA-03, NFR-USA-04

---

### Phase 5e: Duplicate Device ID Anomaly Detection & TUI Fix
- [x] Add `DUPLICATE_DEVICE_ID` anomaly type to `AnomalyType` enum
  - Severity: critical
  - Tracks device instance → set of source IPs (`_instance_ips` dict)
  - Triggers on any packet with a Device-type object identifier (object_type == 8) from a new IP
  - Not limited to I-Am — ReadProperty, WriteProperty, etc. referencing a Device object also trigger detection
  - Non-Device objects (Analog-Input, etc.) correctly ignored
  - Anomaly message lists all conflicting IPs
  - Respects existing cooldown mechanism to avoid alert floods
  - State cleared on `reset()`
- [x] Generate sample pcap: `samples/duplicate_device_id.pcap`
  - 4 devices: Device-1 (Who-Is), Device-2 (I-Am, instance 200), Device-3 (I-Am, instance 200 — duplicate!), Device-4 (I-Am, instance 300)
  - Generator script: `samples/gen_duplicate_device.py`
- [x] Fix AnomalyLog text wrapping in TUI
  - Replaced `Label` with `Static` inside `VerticalScroll` container for word wrapping
  - Added `overflow-y: auto` and `width: 100%` CSS for anomaly panel
- [x] 4 new tests (43 analysis tests total, 134 total across all suites)
  - Duplicate device ID detected from I-Am traffic
  - Duplicate device ID detected from non-I-Am traffic (e.g. ReadProperty)
  - Non-Device objects do not false-positive
  - Same instance from same IP does not trigger

**Requirement coverage:** FR-ANO-09 (duplicate device ID detection), NFR-USA-04 (anomaly log readability)

---

### Phase 5f: Enhanced Broadcast Storm Detection
- [x] Expand broadcast storm detection from Who-Is/I-Am only to 4 sub-type patterns:
  - **Discovery flood** — Who-Is (8), I-Am (0), Who-Has (7), I-Have (1) — unconfirmed services
  - **Time sync flood** — TimeSynchronization (6), UTC-TimeSynchronization (9) — configurable `timesync_pps` threshold (default 10)
  - **Unconfirmed service flood** — UnconfirmedCOVNotification (2), WriteGroup (10) — configurable `unconfirmed_flood_pps` threshold (default 30)
  - **Router discovery flood** — Who-Is-Router-To-Network (0x00), I-Am-Router-To-Network (0x01) — NPDU network messages (no APDU) — configurable `router_discovery_pps` threshold (default 20)
- [x] Add aggregate broadcast rate window across all sub-types
  - Catches mixed-pattern storms that don't exceed any single sub-type threshold
  - Only fires aggregate alert if no sub-type alert already raised for same packet
- [x] Track NPDU global broadcast (DNET=0xFFFF) in anomaly `details["global_broadcast"]`
- [x] All storm anomalies use existing `BROADCAST_STORM` enum value with `details["storm_type"]` for sub-type differentiation
  - Values: `"discovery"`, `"timesync"`, `"unconfirmed"`, `"router"`, `"aggregate"`
- [x] Updated `reset()` to clear all new sub-type rate windows
- [x] Updated sample pcap generator: `samples/gen_broadcast_storm.py`
  - Multi-phase scenario (8 phases): normal discovery → quiet → discovery flood (~60 pps Who-Is + I-Am responses) → calm → TimeSynchronization flood (~15 pps) → calm → router discovery flood (~25 pps Who-Is-Router + I-Am-Router) → recovery
  - New helper functions: `make_time_sync()`, `make_who_is_router()`, `make_i_am_router()`
  - Generates 774 packets across 27.5 seconds
- [x] 7 new tests (50 analysis tests, 171 total across all suites)
  - `test_anomaly_broadcast_storm` — original test updated with `storm_type` assertion
  - `test_anomaly_broadcast_storm_who_has` — Who-Has/I-Have triggers discovery sub-type
  - `test_anomaly_broadcast_storm_timesync` — TimeSynchronization flood triggers timesync sub-type
  - `test_anomaly_broadcast_storm_unconfirmed` — COV notification flood triggers unconfirmed sub-type
  - `test_anomaly_broadcast_storm_router_discovery` — NPDU Who-Is-Router flood (no APDU) triggers router sub-type
  - `test_anomaly_broadcast_storm_aggregate` — mixed traffic below sub-type thresholds triggers aggregate
  - `test_anomaly_broadcast_storm_below_threshold` — sub-threshold traffic does NOT trigger
  - `test_anomaly_broadcast_storm_global_broadcast` — DNET=0xFFFF flagged in details

**Requirement coverage:** FR-ANO-02 (broadcast storm detection — expanded), FR-ANO-08 (operational anomalies)

---

### Phase 5g: User-Adjustable Settings File
- [x] Created `settings.toml` at project root — TOML format, fully commented (later split into `settings_user.toml` + `settings_default.toml`)
  - All anomaly detection thresholds configurable: `chatty_pps`, `broadcast_pps`, `timesync_pps`, `unconfirmed_flood_pps`, `router_discovery_pps`, `error_pps`, `reject_pps`, `abort_pps`
  - General parameters: `window_seconds`, `cooldown_seconds`, `max_anomalies`
- [x] Created `backend/settings.py` — settings loader module
  - `load_settings(path)` reads TOML, falls back to defaults for missing keys
  - `AnomalySettings` dataclass with `to_kwargs()` for direct `AnomalyDetector(**kwargs)` usage
  - Type validation with coercion (int→float), unknown key warnings, malformed file resilience
  - File is optional — missing/deleted file uses built-in defaults
- [x] Added `--settings TOML` CLI flag to `backend/main.py`
  - Default: auto-detects `settings_user.toml` from project root
  - `AnomalyDetector` now instantiated with `**settings.anomaly_kwargs()`
- [x] Updated `samples/gen_broadcast_storm.py` — increased burst intensity so all 3 sub-types (discovery, timesync, router) trigger with default thresholds
  - TimeSynchronization: 160 packets over 8s (~20 pps)
  - Router discovery: 256 packets over 8s (~32 pps)
  - Total: 983 packets over 33.5s
- [x] Per-sub-type cooldown keys — broadcast storm sub-types have independent cooldowns so discovery, timesync, and router alerts fire independently
- [x] 12 new settings tests (183 total across all suites)
  - Defaults, missing file, partial override, integer coercion, full override
  - Unknown key handling, wrong type fallback, empty file, malformed TOML
  - `anomaly_kwargs()` integration with `AnomalyDetector`

**Requirement coverage:** FR-CFG (configurable thresholds), NFR-USR (user-adjustable settings)

---

### Phase 5h: TUI Settings Tab
- [x] `SettingsPanel` widget in `backend/tui/widgets.py`
  - Grouped, labeled Input fields for all 11 anomaly detection parameters
  - `load_values()` / `get_values()` for programmatic access
  - Save and Reset to Defaults buttons
  - Status line for feedback messages
- [x] Settings tab added to TUI (`TabPane` in `TabbedContent`)
  - Settings loaded from file on mount
  - Save button: validates inputs, updates running `AnomalyDetector`, writes to `settings_user.toml`
  - Reset button: copies `settings_default.toml` into `settings_user.toml`, updates detector + UI
  - Changes take effect immediately on the running anomaly detector
- [x] `save_settings()` function in `backend/settings.py`
  - Generates well-commented TOML grouped by category
  - Marks non-default values with `# default: X` comments
  - Round-trip safe: save → load produces identical values
- [x] `get_defaults()` function reads from `settings_default.toml` (falls back to dataclass defaults)
- [x] `reset_to_defaults()` function copies `settings_default.toml` content into `settings_user.toml`
- [x] `--settings` CLI flag wired through `run_tui()` to TUI app
- [x] Textual CSS styles for settings tab layout
- [x] 11 new tests (5 save_settings + 1 get_defaults + 5 TUI settings integration)
  - Save/reload round-trip, readable TOML, non-default marking
  - Settings panel presence, value loading, reset, apply-updates-detector

**Requirement coverage:** FR-CFG (configurable thresholds), NFR-USR-02 (TUI settings editing)

---

### Phase 6: FastAPI Server & WebSocket Streaming
- [ ] Extend `backend/main.py` `--serve` mode — FastAPI app with uvicorn on `127.0.0.1:8765`
  - CORS middleware for future Electron renderer
- [ ] Create `backend/api/__init__.py`
- [ ] Create `backend/api/capture.py` — capture control endpoints
  - `GET /api/health`
  - `GET /api/interfaces`
  - `POST /api/capture/start`
  - `POST /api/capture/stop`
  - `GET /api/capture/status`
  - `POST /api/capture/import`
  - `POST /api/capture/save`
- [ ] Create `backend/api/analysis.py` — analysis data endpoints
  - `GET /api/devices`
  - `GET /api/stats`
  - `GET /api/anomalies`
  - `GET /api/packets?offset=N&limit=M&filter=...`
  - `GET /api/packets/{id}`
- [ ] Create `backend/api/export.py` — export endpoints
  - `GET /api/export/pcap`
  - `GET /api/export/devices?format=csv|json`
  - `GET /api/export/stats?format=csv|json`
  - `GET /api/export/report?format=json`
- [ ] Create `backend/api/ws.py` — WebSocket endpoints
  - `WS /ws/packets` — real-time packet stream
  - `WS /ws/stats` — 1Hz stats updates
  - `WS /ws/anomalies` — real-time anomaly alerts

**Requirement coverage:** FR-CAP-03, FR-CAP-04, FR-CAP-06, FR-CAP-07, FR-EXP-01 through FR-EXP-06, NFR-PER-03, NFR-PER-04, NFR-SEC-01

---

### Phase 7: Session Management & Export
- [ ] Implement pcap save/load in backend
  - Scapy `wrpcap()` to save
  - `rdpcap()` / `PcapReader()` to load
  - Session metadata alongside pcap (start time, interface, duration, device count)
- [ ] Implement export formatters
  - CSV formatter for device list and stats
  - JSON formatter for device list, stats, and full report

**Requirement coverage:** FR-SES-01 through FR-SES-03, FR-EXP-01 through FR-EXP-06

---

### Phase 8: Testing & Robustness (Backend)
- [ ] Create `backend/tests/test_parsers.py`
  - BVLC parser tests with known hex samples
  - NPDU parser tests (all control flag combinations)
  - APDU parser tests (all 8 PDU types, service choices)
  - Edge cases: segmented, forwarded, network layer messages
- [ ] Create `backend/tests/test_analysis.py`
  - Device registry accumulation tests
  - Traffic stats calculation tests
  - Anomaly detection threshold tests
- [ ] Create test pcap fixture file
  - Who-Is/I-Am, ReadProperty/ACK, WriteProperty
  - COV subscriptions, broadcast storms, errors
  - Forwarded NPDUs, network layer messages
- [ ] Performance test
  - Synthetic 2000+ pps workload
  - Verify no packet drops over 5 minutes sustained
  - Verify queue backpressure works correctly

**Requirement coverage:** TEST-01 through TEST-07, TEST-09, NFR-PER-01, NFR-REL-01

---

### Phase 9: Electron Shell
- [ ] Create `electron/main.ts`
  - Spawn Python backend with `--serve` flag (dev: `python`, prod: PyInstaller exe)
  - Health-check polling (30 retries, 500ms delay)
  - Process lifecycle (SIGTERM on macOS, taskkill on Windows)
  - macOS privilege escalation via `osascript`
  - Windows Npcap detection and guidance
- [ ] Create `electron/preload.ts`
  - IPC bridge for file dialogs (pcap import/save)
  - Platform detection exposure to renderer
- [ ] Configure `electron-builder.yml`
  - macOS: `.dmg` + `.pkg` (with BPF permissions post-install script)
  - Windows: NSIS installer
  - `extraResources` for PyInstaller output

**Requirement coverage:** FR-CAP-08, NFR-REL-02, NFR-REL-03, NFR-USA-01, NFR-USA-02

---

### Phase 10: React Frontend (Capture Controls — MVP UI)
- [ ] Set up `frontend/` with Vite + React + TypeScript
- [ ] Create `frontend/src/services/api.ts` — API client
  - REST client for all endpoints
  - WebSocket connection manager (packets, stats, anomalies)
  - Reconnection logic
- [ ] Create `frontend/src/pages/CapturePage.tsx` — main page
  - Interface selector dropdown
  - Start/Stop capture buttons
  - Import pcap button (file dialog)
  - Capture status indicator (running/stopped, duration, packet count)
- [ ] Create `frontend/src/components/PacketTable.tsx`
  - Virtualized scrolling table (100,000+ rows)
  - Columns: #, Timestamp, Source, Dest, BVLC Function, Service, Device Instance, Length
  - Click row → expand full packet decode
  - Auto-scroll with pause on user interaction
- [ ] Create `frontend/src/components/DeviceList.tsx`
  - Sortable/filterable device table
  - Columns: Device Instance, IP, Vendor, Model, Packet Count, Rate, First Seen, Last Seen
- [ ] Create `frontend/src/components/StatsPanel.tsx`
  - Total packets, rate, bytes
  - Service type breakdown
  - Top talkers summary
- [ ] Create `frontend/src/components/AnomalyPanel.tsx`
  - Anomaly list with severity, device, description, timestamp

**Requirement coverage:** FR-INS-01 through FR-INS-06, FR-DEV-06, NFR-PER-05, NFR-USA-03, NFR-USA-04

---

### Phase 11: Cross-Platform Packaging & Verification
- [ ] Cross-platform verification
  - Build and test on macOS (Intel + Apple Silicon)
  - Build and test on Windows
  - Verify Electron packaging produces working installers

**Requirement coverage:** TEST-08

---

## Design Decisions Made During Implementation

> This section is updated as implementation progresses. Each entry records the decision, alternatives considered, and rationale.

| # | Date | Decision | Alternatives Considered | Rationale |
|---|------|----------|------------------------|-----------|
| 1 | 2026-02-11 | Electron + Python backend (not Tauri/Rust) | Tauri+Rust, PyQt, pure Electron | User prefers Python for backend logic |
| 2 | 2026-02-11 | React + TypeScript + Vite (not Svelte/Vue) | Svelte, Vue | Largest ecosystem, best chart/table library support |
| 3 | 2026-02-11 | FastAPI + WebSocket (not Flask/Django) | Flask-SocketIO, Tornado, Django Channels | Async-native, fast, modern WebSocket support |
| 4 | 2026-02-11 | Scapy AsyncSniffer (not pypcap/dpkt) | pypcap, dpkt, pyshark | Most versatile; BPF kernel filter handles BACnet scale |
| 5 | 2026-02-11 | BACpypes3 (not custom parser) | Custom parser, BACpypes legacy, bacnet-stack FFI | Active, async, proven decode_packet() pipeline |
| 6 | 2026-02-11 | Pcap files (not SQLite) | SQLite, pcap+SQLite hybrid | Industry standard, Wireshark-compatible, lighter |
| 7 | 2026-02-11 | Transport abstraction base class | Direct Scapy coupling | Enables future MS/TP (RS-485) without restructuring |
| 8 | 2026-02-11 | Single interface capture (MVP) | Multi-interface simultaneous | Sufficient for MVP; expandable later |
| 9 | 2026-02-11 | Python 3.12+ | 3.10+, 3.8+ | Best async performance, latest stable |
| 10 | 2026-02-11 | PyInstaller --onedir (not --onefile) | --onefile, cx_Freeze, embedded Python | Faster startup (no temp extraction), proven pattern |
| 11 | 2026-02-12 | Backend-first / CLI-first implementation order | Full-stack per phase | Validate core capture+parse+analysis pipeline from terminal before adding UI layers; `--serve` flag enables FastAPI when needed |
| 12 | 2026-02-12 | Manual byte-level parsers as primary (not BACpypes3 decode_packet) | BACpypes3 primary + manual fallback | Full control over all 12 BVLC functions, 20 network message types, 8 PDU types; BACpypes3 can be added later for deeper ASN.1 service data enrichment |
| 13 | 2026-02-12 | Textual TUI as default CLI output (not scrolling terminal) | Rich Live+Layout, curses, urwid, blessed | Asyncio-native, CSS layout, DataTable widget, keyboard nav, built-in testing (Pilot); `--plain` preserves old behavior for scripting/CI |
| 14 | 2026-02-17 | TabbedContent for multi-view TUI (not single-page scroll) | Multiple apps, screen switching, manual tab bar | Textual built-in TabbedContent/TabPane — zero custom plumbing, keyboard-navigable, auto-styled; separate concerns (traffic monitoring vs device inventory) into distinct views |

---

## Known Risks & Open Questions

| # | Risk / Question | Status | Notes |
|---|----------------|--------|-------|
| 1 | Scapy performance at 2000+ pps | Open | BPF filter should reduce load; needs performance testing |
| 2 | Npcap licensing for redistribution | Open | May need to instruct users to install Npcap separately |
| 3 | macOS BPF device permissions | Open | `.pkg` post-install script vs runtime `osascript` elevation |
| 4 | BACpypes3 decode_packet() coverage | Resolved | Manual byte-level parsers implemented as primary; BACpypes3 available for future ASN.1 enrichment |
| 5 | Electron + PyInstaller bundle size | Open | Estimate ~150MB+ total; acceptable for desktop app |
| 6 | WebSocket backpressure to frontend | Open | If frontend can't keep up with /ws/packets at high rates |
| 7 | Scapy hidden imports for PyInstaller | Open | Need to identify all required `--hidden-import` flags |

---

## Completed Milestones

| Date | Milestone |
|------|-----------|
| 2026-02-11 | Research complete — BACnet/IP protocol, BACpypes3, Scapy, Electron+Python architecture |
| 2026-02-11 | Requirements document complete — all FR/NFR/TEST requirements defined |
| 2026-02-11 | Planning complete — 9-phase implementation plan with requirement traceability |
| 2026-02-11 | Session progress tracking document created |
| 2026-02-12 | Reordered to 11-phase backend-first plan — CLI-runnable before any frontend work |
| 2026-02-12 | Phase 1 complete — Python project scaffolded, all deps installed, Pydantic models defined |
| 2026-02-12 | Phase 2 complete — Transport abstraction layer with BACnetIPCapture and PcapReplayCapture |
| 2026-02-12 | Phase 3 complete — BVLC/NPDU/APDU parsers + pipeline, 56 test cases passing |
| 2026-02-12 | Phase 4 complete — Analysis engine (device registry, traffic stats, anomaly detector, packet inspector), 39 test cases passing |
| 2026-02-12 | Phase 5 complete — CLI entry point with argparse, async pipeline, terminal output, JSONL save, 35 test cases passing |
| 2026-02-12 | Phase 5b complete — Textual TUI dashboard (top-style fixed panels), --plain/--tui-packets flags, 30 test cases, 160 total passing |
| 2026-02-13 | Phase 5c complete — PacketDetailPanel, live filter, PDU Type/Object columns, APDU model extensions (I-Am, Who-Is, property ID), parser enrichment, layout refinements |
| 2026-02-17 | Phase 5d complete — TUI tabbed interface with TabbedContent; Devices tab with full DeviceListPanel DataTable (IP, device ID, object type, vendor, traffic stats, timestamps) |
| 2026-02-19 | Phase 5e complete — Duplicate device ID anomaly detection (any Device-type object, not just I-Am); AnomalyLog text wrapping fix; sample pcap with duplicate IDs; 134 tests passing |
| 2026-02-19 | Phase 5f complete — Enhanced broadcast storm detection: 4 sub-type patterns (discovery, timesync, unconfirmed, router) + aggregate; multi-pattern sample pcap; 171 tests passing |
| 2026-02-19 | Phase 5g complete — User-adjustable settings.toml; settings loader with validation/fallback; --settings CLI flag; per-sub-type cooldowns; pcap burst intensity increased; 183 tests passing |
| 2026-02-19 | Phase 5h complete — TUI Settings tab: SettingsPanel widget, save/reset buttons, live detector updates, save_settings() TOML writer, get_defaults(); 194 tests passing |
| 2026-02-19 | Settings restructured to two-file architecture: settings_user.toml (active) + settings_default.toml (immutable defaults); reset_to_defaults() copies defaults to user file; 197 tests passing |

---

## Next Steps

**Ready to begin Phase 6: FastAPI Server & WebSocket Streaming**
1. Extend `backend/main.py` `--serve` mode — FastAPI app with uvicorn on `127.0.0.1:8765`
2. Create REST endpoints for capture control, analysis data, and export
3. Create WebSocket endpoints for real-time packet/stats/anomaly streaming
4. Test with curl and wscat

**Goal:** By end of Phase 6, run `uv run python backend/main.py --serve` and consume live BACnet data via REST/WebSocket from any HTTP client.
