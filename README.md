# NetSight

A cross-platform desktop BACnet/IP network traffic analyzer for building automation engineers.

NetSight passively captures BACnet/IP traffic, parses it at all protocol layers (BVLC → NPDU → APDU), and provides real-time analysis including device discovery, traffic statistics, service breakdowns, and anomaly detection.

## Quick Start

```bash
# Install dependencies (uses uv — https://docs.astral.sh/uv/)
uv sync

# Live capture on an interface (requires root/admin)
sudo uv run python -m backend.main -i en0

# Analyze a pcap file
uv run python -m backend.main -f capture.pcap

# Plain scrolling output (no TUI — for scripting/piping/CI)
uv run python -m backend.main -f capture.pcap --plain

# Start API server for frontend consumers
uv run python -m backend.main --serve

# Use a custom settings file
uv run python -m backend.main -f capture.pcap --settings my_user_settings.toml

# Run tests
uv run python -m pytest backend/tests/
```

## TUI Dashboard

The default mode launches a Textual TUI dashboard with three tabs:

- **Traffic** — Live packet table with filtering, traffic stats, device summary, top talkers, packet detail view, and anomaly log
- **Devices** — Full device list with IP, device ID, object type, vendor, traffic stats, and timestamps
- **Settings** — View and edit anomaly detection thresholds; changes apply immediately and persist across sessions

Keyboard shortcuts: **Q** quit, **P** pause/resume, **S** save packets to JSONL.

## Settings

Anomaly detection thresholds are configurable via `user_settings.toml` in the project root. Edit the file directly or use the TUI Settings tab.

Configurable parameters include: chatty device threshold, broadcast storm sub-type thresholds (discovery, timesync, unconfirmed, router), error/reject/abort rates, sliding window duration, alert cooldown, and max anomaly records.

Built-in defaults are stored in `default_settings.toml` (do not edit). To restore defaults, use the "Reset to Defaults" button in the TUI Settings tab, which copies `default_settings.toml` into `user_settings.toml`.

## Project Structure

```
backend/                Python 3.12+ — capture, parsing, analysis, TUI, settings, CLI
user_settings.toml      Active user settings (TOML, editable)
default_settings.toml   Built-in default settings (TOML, do not edit)
samples/                Sample pcap files for testing and development
frontend/         React + TypeScript + Vite (later phases)
electron/         Electron desktop shell (later phases)
```

## Documentation

- [Requirements](requirements.md) — functional/non-functional requirements, API spec
- [Research](research.md) — BACnet protocol reference, technology decisions
- [Session Progress](session_progress.md) — implementation checklist and design decisions
