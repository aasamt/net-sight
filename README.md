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
uv run python -m backend.main -f capture.pcap --settings my_settings_user.toml

# Run tests
uv run python -m pytest backend/tests/
```

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
