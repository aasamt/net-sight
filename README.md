# NetSight

A cross-platform desktop BACnet/IP network traffic analyzer for building automation engineers.

NetSight passively captures BACnet/IP traffic, parses it at all protocol layers (BVLC → NPDU → APDU), and provides real-time analysis including device discovery, traffic statistics, service breakdowns, and anomaly detection.

---

## Prerequisites

### 1. Install Python 3.12+

NetSight requires **Python 3.12 or later**.

**macOS** (using [Homebrew](https://brew.sh/)):
```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.12
```

**macOS** (official installer):
Download from https://www.python.org/downloads/macos/ and run the `.pkg` installer.

**Windows** (official installer):
1. Download from https://www.python.org/downloads/windows/
2. Run the installer and **check "Add Python to PATH"** during setup
3. Verify: open Command Prompt and run `python --version`

**Linux (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install python3.12 python3.12-venv python3.12-dev
```

**Linux (Fedora):**
```bash
sudo dnf install python3.12
```

Verify Python is installed:
```bash
python3 --version   # Should show 3.12.x or later
```

### 2. Install uv (Python Package Manager)

NetSight uses [uv](https://docs.astral.sh/uv/) for dependency management. It replaces pip and virtualenvs.

**macOS / Linux:**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Windows (PowerShell):**
```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**Alternative** (using pip if you prefer):
```bash
pip install uv
```

Verify uv is installed:
```bash
uv --version
```

### 3. Platform-Specific Packet Capture Requirements

NetSight uses raw packet capture, which requires additional platform setup for **live capture** (not needed for pcap file analysis).

**macOS:**
- Live capture requires root privileges (BPF device access). Run with `sudo`.
- No additional drivers needed.

**Windows:**
- Install [Npcap](https://npcap.com/) — required for packet capture on Windows.
  1. Download from https://npcap.com/#download
  2. Run the installer and **check "Install Npcap in WinPcap API-compatible Mode"**
  3. Restart your terminal after installation

**Linux:**
- Live capture requires root privileges or the `CAP_NET_RAW` capability.
- libpcap is usually pre-installed. If not: `sudo apt install libpcap-dev` (Debian/Ubuntu) or `sudo dnf install libpcap-devel` (Fedora).

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/net_sight.git
cd net_sight

# Install all dependencies (creates a virtual environment automatically)
uv sync

# Install dev dependencies too (pytest, ruff) — optional, for development
uv sync --dev
```

`uv sync` reads `pyproject.toml`, creates a `.venv` virtual environment in the project directory, and installs all required packages:

| Package | Purpose |
|---------|---------|
| `scapy` | Raw packet capture (AsyncSniffer) |
| `bacpypes3` | BACnet protocol library |
| `pydantic` | Data models and validation |
| `textual` | Terminal UI (TUI) dashboard |
| `fastapi` + `uvicorn` | REST API & WebSocket server |
| `websockets` | WebSocket support |

---

## Quick Start

### Analyze a pcap file (no root required)

```bash
uv run python -m backend.main -f samples/test_bacnet.pcap
```

This launches the TUI dashboard with the parsed pcap data. No live capture permissions needed.

### Live capture on a network interface (requires root/admin)

**macOS / Linux:**
```bash
# List available network interfaces
sudo uv run python -m backend.main --list-interfaces

# Capture on a specific interface
sudo uv run python -m backend.main -i en0
```

**Windows (run Command Prompt as Administrator):**
```cmd
uv run python -m backend.main -i "Ethernet"
```

### Plain text output (no TUI — for scripting/piping/CI)

```bash
uv run python -m backend.main -f capture.pcap --plain
```

### Start API server for frontend consumers

```bash
uv run python -m backend.main --serve
```

### Use a custom settings file

```bash
uv run python -m backend.main -f capture.pcap --settings my_settings.toml
```

### Run tests

```bash
uv run python -m pytest backend/tests/
```

---

## TUI Dashboard

The default mode launches a Textual TUI dashboard with tabs:

- **Traffic** — Live packet table with Wireshark-style filtering, traffic stats, device summary, top talkers, packet detail view, and anomaly log
- **Devices** — Full device list with IP, device ID, object type, vendor, traffic stats, and timestamps
- **Commands** — Send BACnet commands (Who-Is broadcast with optional device ID range). Only available during live capture.
- **Settings** — View and edit anomaly detection thresholds; changes apply immediately and persist across sessions

Keyboard shortcuts: **Q** quit, **P** pause/resume, **S** save packets to JSONL.

## Packet Filter Reference

The filter field in the Traffic tab supports Wireshark-style expressions. Type a filter and results update live.

### Filter Fields

| Field | Aliases | Description | Column |
|-------|---------|-------------|--------|
| `src` | `source`, `ip.src` | Source IP address | Source |
| `dst` | `dest`, `destination`, `ip.dst` | Destination IP address | Destination |
| `pdu` | `pdu_type`, `type` | PDU type name | PDU Type |
| `service` | `svc` | BACnet service name | Service |
| `object` | `obj` | Object type and instance | Object |
| `size` | `length`, `len` | Packet size in bytes | Size |

### Operators

| Operator | Meaning | Example |
|----------|---------|--------|
| `==` | Exact match (case-insensitive) | `src == 192.168.1.10` |
| `!=` | Not equal | `dst != 255.255.255.255` |
| `contains` | Substring match | `service contains Read` |
| `&&` | AND — both sides must match | `src == 10.0.0.5 && pdu == Confirmed-REQ` |
| `\|\|` | OR — either side matches | `service == Who-Is \|\| service == I-Am` |

Precedence: `&&` binds tighter than `||`.

### Syntax Styles

**Operator syntax** — `field operator value`:
```
src == 192.168.1.10
dst != 10.0.0.255
service contains Read
pdu == Unconfirmed-REQ
obj contains Device
size == 64
```

**Key:value shorthand** — `field:value` (uses substring/contains matching):
```
src:192.168.1.10
service:ReadProperty
obj:Device
```

**Plain text** — no field or operator (searches all columns, backward compatible):
```
ReadProperty
192.168
Who-Is
```

### Combining Filters

**AND** — all conditions must match:
```
src == 10.0.0.5 && service == ReadProperty
src == 192.168.1.10 && pdu == Confirmed-REQ && obj contains Device
```

**OR** — any condition matches:
```
service == Who-Is || service == I-Am
src == 10.0.0.5 || src == 192.168.1.20
```

**Mixed** — `&&` evaluated before `||`:
```
src == 10.0.0.5 && service == ReadProperty || service == Who-Is
```
This matches packets where (source is 10.0.0.5 AND service is ReadProperty) OR (service is Who-Is).

**Multiple key:value** — space-separated, implicitly ANDed:
```
src:10.0.0.5 service:Read
dst:192.168 pdu:Confirmed
```

### Common Filter Examples

| Goal | Filter |
|------|--------|
| Show only packets from a specific device | `src == 192.168.1.10` |
| Show only ReadProperty requests | `service == ReadProperty` |
| Show all discovery traffic | `service == Who-Is \|\| service == I-Am` |
| Show packets to broadcast | `dst:255` |
| Show confirmed requests only | `pdu == Confirmed-REQ` |
| Show errors and rejects | `pdu:Error \|\| pdu:Reject` |
| Show traffic involving a specific device object | `obj contains Device-200` |
| Hide a noisy source | `src != 10.0.0.99` |
| Show large packets | `size == 128` |
| Show ReadProperty from a specific source | `src == 10.0.0.5 && service contains Read` |
| Show all analog input objects | `obj contains AnalogInput` |

## Commands

The Commands tab (live capture only) allows sending BACnet service requests to the network:

- **Who-Is Broadcast** — Discover BACnet devices. Optionally specify a device instance range (Low/High Device ID, defaults: 0–4194303). Responses (I-Am) appear in the Traffic tab.

## Settings

Anomaly detection thresholds are configurable via `settings_user.toml` in the project root. Edit the file directly or use the TUI Settings tab.

Configurable parameters include: chatty device threshold, broadcast storm sub-type thresholds (discovery, timesync, unconfirmed, router), error/reject/abort rates, sliding window duration, alert cooldown, and max anomaly records.

Built-in defaults are stored in `settings_default.toml` (do not edit). To restore defaults, use the "Reset to Defaults" button in the TUI Settings tab, which copies `settings_default.toml` into `settings_user.toml`.

## Project Structure

```
backend/                Python 3.12+ — capture, parsing, analysis, TUI, settings, CLI
settings_user.toml      Active user settings (TOML, editable)
settings_default.toml   Built-in default settings (TOML, do not edit)
samples/                Sample pcap files for testing and development
frontend/         React + TypeScript + Vite (later phases)
electron/         Electron desktop shell (later phases)
```

## Documentation

- [Requirements](requirements.md) — functional/non-functional requirements, API spec
- [Research](research.md) — BACnet protocol reference, technology decisions
- [Session Progress](session_progress.md) — implementation checklist and design decisions

## Troubleshooting

### `uv: command not found`

The uv installer adds itself to your shell profile. Restart your terminal or run:
```bash
source ~/.bashrc    # Linux (bash)
source ~/.zshrc     # macOS (zsh)
```

On Windows, close and reopen PowerShell/Command Prompt.

### `python3: command not found` or wrong version

Ensure Python 3.12+ is installed and on your PATH:
```bash
python3 --version
# or on Windows:
python --version
```

If you have multiple Python versions, uv will select the correct one based on `requires-python` in `pyproject.toml`.

### `Permission denied` during live capture

Live packet capture requires elevated privileges:
- **macOS / Linux:** Prefix the command with `sudo`
- **Windows:** Right-click Command Prompt → "Run as administrator"

```bash
sudo uv run python -m backend.main -i en0
```

### `OSError: No such device` or no interfaces found

- Verify the interface name: run `ifconfig` (macOS/Linux) or `ipconfig` (Windows)
- On macOS, common interface names: `en0` (Wi-Fi), `en1` (Ethernet)
- On Windows, use the adapter name shown in `ipconfig`, e.g., `"Ethernet"` or `"Wi-Fi"`

### `Npcap is not installed` (Windows only)

Download and install Npcap from https://npcap.com/#download. Check "Install Npcap in WinPcap API-compatible Mode" during installation. Restart your terminal after installing.

### `ModuleNotFoundError` or missing dependencies

Re-run dependency installation:
```bash
uv sync
```

If `.venv` is corrupted, delete it and re-sync:
```bash
rm -rf .venv
uv sync
```
