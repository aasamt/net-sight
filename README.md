# NetSight

A cross-platform desktop BACnet/IP network traffic analyzer for building automation engineers.

NetSight passively captures BACnet/IP traffic, parses it at all protocol layers (BVLC → NPDU → APDU), and provides real-time analysis including device discovery, traffic statistics, service breakdowns, and anomaly detection.

## Quick Start

```bash
# Install dependencies
cd backend
pip install -e .

# Live capture on an interface (requires root/admin)
sudo python -m backend.main -i en0

# Analyze a pcap file
python -m backend.main -f capture.pcap

# Start API server for frontend consumers
python -m backend.main --serve
```

## Project Structure

```
backend/          Python 3.12+ — capture, parsing, analysis, CLI, FastAPI server
frontend/         React + TypeScript + Vite (later phases)
electron/         Electron desktop shell (later phases)
```

## Documentation

- [Requirements](requirements.md) — functional/non-functional requirements, API spec
- [Research](research.md) — BACnet protocol reference, technology decisions
- [Session Progress](session_progress.md) — implementation checklist and design decisions
