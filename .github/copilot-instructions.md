# NetSight — AI Coding Instructions

## Project Overview

NetSight is a cross-platform desktop BACnet/IP network traffic analyzer. It captures, parses, and analyzes BACnet protocol traffic for building automation engineers.

**Stack:** Python 3.12+/FastAPI (backend & CLI) → Electron (shell, later) → React/TypeScript/Vite (frontend, later)
**Package Manager:** uv (https://docs.astral.sh/uv/) — use `uv run` to execute commands, `uv sync` to install deps
**IPC:** HTTP REST + WebSocket on `127.0.0.1:8765` (when `--serve` flag is used)

## Implementation Strategy

Backend-first: the Python backend runs standalone from the terminal before any frontend exists.
- **Default mode (TUI):** `uv run python backend/main.py -i en0` — live capture with Textual TUI dashboard (top-style fixed panels)
- **Pcap replay (TUI):** `uv run python backend/main.py -f capture.pcap` — import and analyze with TUI dashboard; shows "Replay complete" and keeps dashboard open for inspection
- **Plain mode:** `uv run python backend/main.py -i en0 --plain` — scrolling terminal output (original behavior, for scripting/piping/CI)
- **Server mode:** `uv run python backend/main.py --serve` — starts FastAPI on `127.0.0.1:8765` for REST/WebSocket consumers

Electron and React are built on top of the `--serve` mode in later phases.

## Architecture & Data Flow

```
Scapy AsyncSniffer (capture thread, BPF: udp port 47808)
  → asyncio.Queue (maxsize=10000, thread-safe bridge via loop.call_soon_threadsafe)
  → Parser Pipeline (BVLC → NPDU → APDU, manual byte-level parsers)
  → Analysis Engine (device registry, traffic stats, anomaly detector)
  → TUI dashboard (default) or WebSocket broadcast (--serve mode)
```

Three IPC consumers: React renderer uses REST for request/response, WebSocket for real-time streaming. Electron main process manages Python backend lifecycle (spawn, health-check polling, SIGTERM/taskkill on quit).

## Project Structure

```
backend/                     # Python 3.12+, FastAPI
  main.py                    # CLI entry point: TUI (default), --plain, or --serve
  settings.py                # Settings loader/writer (TOML → AnomalySettings dataclass)
  models/                    # Shared Pydantic models (BVLCMessage, NPDUMessage, APDUMessage, ParsedPacket)
  transport/base.py          # TransportCapture abstract base class
  transport/bacnet_ip.py     # BACnetIPCapture — Scapy AsyncSniffer
  transport/pcap_replay.py   # PcapReplayCapture — pcap file import
  parsers/{bvlc,npdu,apdu}.py  # Per-layer parsers (separated by protocol layer)
  parsers/pipeline.py        # Full decode orchestration
  analysis/                  # device_registry, traffic_stats, anomaly_detector, packet_inspector
  tui/                       # Textual TUI dashboard (tabbed: Traffic, Devices, Settings)
    app.py                   # NetSightApp(App) — main TUI application
    widgets.py               # PacketTable, StatsPanel, DevicePanel, DeviceListPanel, AnomalyLog, SettingsPanel
    styles.tcss              # Textual CSS for panel layout and colors
  api/                       # capture, analysis, export REST + ws WebSocket endpoints (--serve mode)
  tests/                     # Parser, analysis, settings, TUI, and CLI unit tests
settings.toml                # User-adjustable anomaly detection thresholds (project root)
settings_user.toml           # Active user settings (editable)
settings_default.toml        # Built-in default settings (do not edit)
samples/                     # Sample pcap files for testing and development
frontend/                    # Vite + React 18+ + TypeScript 5+ (later phases)
electron/                    # main.ts (spawn Python), preload.ts (IPC bridge) (later phases)
```

## Critical Conventions

- **Transport abstraction:** All capture sources extend `TransportCapture` base class with `start()`, `stop()`, `list_interfaces()`, `on_packet(callback)`. This enables future MS/TP (RS-485) support without restructuring.
- **Parser separation:** One module per BACnet layer — `bvlc.py`, `npdu.py`, `apdu.py`. Each returns a Pydantic model. `pipeline.py` orchestrates the full decode.
- **Analysis separation:** One module per concern — `device_registry.py`, `traffic_stats.py`, `anomaly_detector.py`. All fed from the same parsed packet stream.
- **Models:** Use Pydantic for all data models (`BVLCMessage`, `NPDUMessage`, `APDUMessage`, `ParsedPacket`).
- **Settings:** Two-file architecture at project root — `settings_user.toml` (active, editable) and `settings_default.toml` (immutable reference). `backend/settings.py` loads from `settings_user.toml`, saves to `settings_user.toml`, and `reset_to_defaults()` copies `settings_default.toml` into `settings_user.toml`. The TUI Settings tab provides live editing with Save and Reset to Defaults. Settings persist across sessions.
- **Scapy config:** Always use `store=False`, BPF filter `udp port 47808`, immediate mode. Minimize work in `prn` callback — queue raw data only.
- **Queue backpressure:** Drop oldest on overflow (`put_nowait` with `QueueFull` exception swallowed), never block the capture thread.
- **Backend security:** FastAPI binds to `127.0.0.1` only. No external access.

## BACnet Protocol Quick Reference

- **UDP port 47808 (0xBAC0)**. Packets have 3 layers: BVLC (data-link, type always `0x81`) → NPDU (network, version `0x01`) → APDU (application).
- **Manual byte-level parsers** are the primary decoders (per design decision #12). BACpypes3 is available for future ASN.1 service data enrichment.
- **Forwarded-NPDU** (BVLC function `0x04`): contains a 6-byte originating IP address that must be extracted for correct device attribution.
- **Object identifiers** are 32-bit: upper 10 bits = object type, lower 22 bits = instance number.
- Device discovery comes from **I-Am** responses (unconfirmed service 0x00).

## Key Dependencies & Their Roles

Managed via `uv` with `pyproject.toml`. Use `uv sync` to install, `uv run` to execute.

| Python Package | Role |
|---|---|
| `fastapi` + `uvicorn[standard]` | REST API + WebSocket server |
| `scapy` | Packet capture (AsyncSniffer), NO built-in BACnet layer |
| `bacpypes3` | BACnet protocol decode (BVLC, NPDU, APDU) |
| `pydantic` | Data models and validation |
| `textual` | TUI dashboard — tabbed interface (Traffic, Devices, Settings tabs), DataTable, TabbedContent, Input forms, keyboard nav |

## Platform-Specific Concerns

- **macOS:** `/dev/bpf*` access requires root or privilege escalation via `osascript`
- **Windows:** Requires Npcap driver; provide user guidance if missing
- **Bundling:** PyInstaller `--onedir` for Python; electron-builder for app. Build per-OS (not cross-compilable).

## Code Style & Conventions

- **Linter/Formatter:** Ruff (replaces black, isort, flake8). Line length: 100.
- **Naming:** PEP 8 — `snake_case` functions/variables, `PascalCase` classes, `UPPER_SNAKE` constants.
- **Type hints:** Required on all function signatures.
- **Commits:** Conventional commits — `type(scope): description`
  - Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`
  - Scopes: `transport`, `parsers`, `analysis`, `api`, `cli`, `tui`, `models`, `settings`
  - Example: `feat(parsers): implement BVLC layer decoder`
- **Branches:** `main` (stable) + `feat/<name>` per phase or major feature.

## Implementation Tracking

Read `session_progress.md` for the 11-phase implementation checklist with requirement traceability. Phases 1-8 are backend/CLI focused. Phases 9-11 add Electron, React, and cross-platform packaging. Update checkbox status as phases complete. Reference `requirements.md` for FR/NFR/TEST IDs when implementing features.

## Testing Patterns

- Parser tests use known hex byte samples for each layer
- Analysis tests verify accumulation and threshold logic
- Use pcap fixture files with representative BACnet traffic
- Performance target: 2000+ pps sustained without drops
- Malformed packets must be logged and skipped, never crash the app
