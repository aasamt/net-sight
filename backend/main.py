"""NetSight CLI entry point — BACnet/IP network traffic analyzer.

Usage:
    python -m backend.main -i en0              # Live capture with TUI dashboard
    python -m backend.main -f capture.pcap     # Replay pcap with TUI dashboard
    python -m backend.main -i en0 --plain      # Scrolling terminal output (no TUI)
    python -m backend.main -i en0 --serve      # Start FastAPI server (Phase 6)

The default mode launches a Textual TUI dashboard (top-style fixed panels).
Use --plain for the original scrolling terminal output (scripting/piping/CI).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys

from backend.analysis.anomaly_detector import AnomalyDetector
from backend.analysis.device_registry import DeviceRegistry
from backend.analysis.packet_processor import PacketProcessor
from backend.analysis.traffic_stats import TrafficStats
from backend.settings import load_settings
from backend.transport.bacnet_ip import BACnetIPCapture
from backend.transport.base import RawPacket
from backend.transport.pcap_replay import PcapReplayCapture

VERSION = "0.1.0"

logger = logging.getLogger("netsight")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="netsight",
        description="NetSight — BACnet/IP network traffic analyzer",
    )

    # Input source (mutually exclusive — validated manually to allow --list-interfaces)
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "-i", "--interface",
        metavar="IFACE",
        help="Network interface for live capture (e.g., en0, eth0)",
    )
    source.add_argument(
        "-f", "--file",
        metavar="PCAP",
        help="Pcap file to replay and analyze",
    )

    # Output
    parser.add_argument(
        "-o", "--save",
        metavar="FILE",
        help="Save parsed packets to JSONL file",
    )

    # Tuning
    parser.add_argument(
        "--stats-interval",
        type=int,
        default=10,
        metavar="SEC",
        help="Periodic stats interval in seconds (default: 10, 0 to disable)",
    )
    parser.add_argument(
        "--replay-speed",
        type=float,
        default=0.0,
        metavar="MULT",
        help="Pcap replay speed multiplier (0 = max speed, 1.0 = real-time)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress per-packet output, only show stats and anomalies",
    )

    # Server mode (Phase 6 stub)
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start FastAPI server on 127.0.0.1:8765 (not yet implemented)",
    )

    # Output mode
    parser.add_argument(
        "--plain",
        action="store_true",
        help="Use scrolling terminal output instead of TUI dashboard",
    )
    parser.add_argument(
        "-n", "--tui-packets",
        type=int,
        default=50,
        metavar="N",
        help="Max recent packets in TUI table (default: 50)",
    )

    # Settings
    parser.add_argument(
        "--settings",
        metavar="TOML",
        default=None,
        help="Path to settings_user.toml (default: auto-detect from project root)",
    )

    # Utility
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    return parser


# ---------------------------------------------------------------------------
# Terminal output helpers
# ---------------------------------------------------------------------------

HEADER = (
    f"{'#':<8} {'Source':<15}   {'Destination':<15}  "
    f"{'BVLC Function':<20} {'Service':<30} {'Size':>6}"
)
SEPARATOR = "─" * len(HEADER)


def print_header() -> None:
    """Print the packet table header."""
    print(f"\n{HEADER}")
    print(SEPARATOR)


def format_stats_block(
    stats: TrafficStats,
    registry: DeviceRegistry,
    detector: AnomalyDetector,
) -> str:
    """Format a boxed stats summary for terminal display."""
    summary = stats.get_summary()
    rates = stats.get_rates()
    top_talkers = stats.get_top_talkers(5)
    devices = registry.get_all_devices()
    anomaly_count = detector.get_anomaly_count()

    lines: list[str] = []
    lines.append("")
    lines.append("┌" + "─" * 62 + "┐")
    lines.append(f"│ {'TRAFFIC STATISTICS':^60} │")
    lines.append("├" + "─" * 62 + "┤")

    # Global counters
    total_pkt = summary["total_packets"]
    total_bytes = summary["total_bytes"]
    duration = summary["duration_seconds"]
    lines.append(f"│  Packets: {total_pkt:<10}  Bytes: {total_bytes:<12}  "
                 f"Duration: {duration:.1f}s     │")

    # Rates
    r1 = rates["1s"]
    r10 = rates["10s"]
    lines.append(f"│  Rate (1s): {r1['pps']:.1f} pps / {r1['bps']:.0f} Bps"
                 f"    (10s): {r10['pps']:.1f} pps / {r10['bps']:.0f} Bps   │")

    # Service mix
    conf_count = summary["confirmed_count"]
    unconf_count = summary["unconfirmed_count"]
    err_count = summary["error_count"]
    rej_count = summary["reject_count"]
    lines.append(f"│  Confirmed: {conf_count:<6}  Unconfirmed: {unconf_count:<6}  "
                 f"Errors: {err_count:<4}  Rejects: {rej_count:<4}│")

    # Devices
    lines.append(f"│  Devices discovered: {len(devices):<6}  "
                 f"Anomalies: {anomaly_count:<34}│")

    # Top talkers
    if top_talkers:
        lines.append("├" + "─" * 62 + "┤")
        lines.append(f"│ {'TOP TALKERS':^60} │")
        for t in top_talkers:
            ip = t["ip"]
            pkt = t["packet_count"]
            pct = t["percent"]
            lines.append(f"│  {ip:<18} {pkt:>8} pkts  ({pct:>5.1f}%)"
                         f"{'':>24}│")

    lines.append("└" + "─" * 62 + "┘")
    lines.append("")

    return "\n".join(lines)


def format_final_report(
    stats: TrafficStats,
    registry: DeviceRegistry,
    detector: AnomalyDetector,
) -> str:
    """Format the final report printed on shutdown."""
    lines: list[str] = []
    lines.append("")
    lines.append("=" * 64)
    lines.append(f"  {'NETSIGHT — FINAL REPORT':^60}")
    lines.append("=" * 64)

    # Summary
    summary = stats.get_summary()
    lines.append(f"\n  Total packets:   {summary['total_packets']}")
    lines.append(f"  Total bytes:     {summary['total_bytes']}")
    lines.append(f"  Duration:        {summary['duration_seconds']:.2f}s")
    lines.append(f"  Confirmed:       {summary['confirmed_count']}")
    lines.append(f"  Unconfirmed:     {summary['unconfirmed_count']}")
    lines.append(f"  Errors:          {summary['error_count']}")
    lines.append(f"  Rejects:         {summary['reject_count']}")
    lines.append(f"  Aborts:          {summary['abort_count']}")

    # Devices
    devices = registry.get_all_devices()
    lines.append(f"\n  Devices discovered: {len(devices)}")
    for dev in devices:
        lines.append(f"    Device:{dev.instance:<8} at {dev.ip}:{dev.port}"
                     f"  ({dev.packet_count} pkts)")

    # Top talkers
    top_talkers = stats.get_top_talkers(10)
    if top_talkers:
        lines.append("\n  Top Talkers:")
        for t in top_talkers:
            lines.append(f"    {t['ip']:<18}  {t['packet_count']:>8} pkts"
                         f"  ({t['percent']:>5.1f}%)")

    # Service breakdown
    services = stats.get_service_breakdown()
    if services:
        lines.append("\n  Service Breakdown:")
        for s in services[:10]:
            lines.append(f"    {s['name']:<30}  {s['packet_count']:>8} pkts")

    # Anomalies
    anomalies = detector.get_recent_anomalies(20)
    if anomalies:
        lines.append(f"\n  Anomalies ({detector.get_anomaly_count()} total):")
        for a in anomalies:
            lines.append(f"    [{a.severity.upper():<8}] {a.message}")

    lines.append("\n" + "=" * 64)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core async pipeline
# ---------------------------------------------------------------------------

async def run_capture(args: argparse.Namespace) -> None:
    """Run the packet capture → parse → analyze → display pipeline."""
    loop = asyncio.get_running_loop()

    # --- Settings & shared processor ---
    settings = load_settings(args.settings) if args.settings else load_settings()
    if settings.settings_path:
        logger.info("Loaded settings from %s", settings.settings_path)

    processor = PacketProcessor(settings=settings)
    device_registry = processor.device_registry
    traffic_stats = processor.traffic_stats
    anomaly_detector = processor.anomaly_detector

    # --- Packet queue (thread-safe bridge) ---
    queue: asyncio.Queue[RawPacket] = asyncio.Queue(maxsize=10_000)
    dropped_count = 0

    def enqueue(raw: RawPacket) -> None:
        """Put a raw packet on the queue (called from event loop via call_soon_threadsafe)."""
        nonlocal dropped_count
        try:
            queue.put_nowait(raw)
        except asyncio.QueueFull:
            dropped_count += 1

    # --- Transport setup ---
    if args.interface:
        transport = BACnetIPCapture(interface=args.interface)
        # Live capture: sniffer thread → call_soon_threadsafe → queue
        transport.on_packet(lambda raw: loop.call_soon_threadsafe(enqueue, raw))
    else:
        transport = PcapReplayCapture(
            file_path=args.file,
            replay_speed=args.replay_speed,
        )
        # Pcap replay: already in event loop thread, can enqueue directly
        transport.on_packet(enqueue)

    # --- JSONL output file ---
    jsonl_file = None
    if args.save:
        jsonl_file = open(args.save, "w", encoding="utf-8")  # noqa: SIM115

    # --- Shutdown coordination ---
    shutdown_event = asyncio.Event()
    packet_count = 0

    def handle_signal(sig: int, _frame: object) -> None:
        """Signal handler — trigger graceful shutdown."""
        sig_name = signal.Signals(sig).name
        logger.info("Received %s, shutting down...", sig_name)
        loop.call_soon_threadsafe(shutdown_event.set)

    # Install signal handlers (only on main thread)
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, handle_signal)
    else:
        signal.signal(signal.SIGINT, handle_signal)

    # --- Consumer coroutine ---
    async def consume_packets() -> None:
        """Drain the queue: parse → analyze → display."""
        nonlocal packet_count

        while not shutdown_event.is_set() or not queue.empty():
            try:
                raw = await asyncio.wait_for(queue.get(), timeout=0.5)
            except TimeoutError:
                continue

            # Parse + analyze via shared processor
            result = processor.process(raw)
            packet_count += 1

            # Display per-packet output
            if not args.quiet:
                print(result.parsed.summary)

            # Print anomaly alerts inline
            for anomaly in result.anomalies:
                print(f"  ⚠ [{anomaly.severity.upper()}] {anomaly.message}")

            # Save to JSONL
            if jsonl_file:
                jsonl_file.write(result.parsed.model_dump_json() + "\n")

    # --- Periodic stats coroutine ---
    async def print_periodic_stats() -> None:
        """Print stats block at regular intervals."""
        if args.stats_interval <= 0:
            return

        while not shutdown_event.is_set():
            await asyncio.sleep(args.stats_interval)
            if shutdown_event.is_set():
                break
            if traffic_stats.total_packets > 0:
                block = format_stats_block(traffic_stats, device_registry, anomaly_detector)
                print(block)
                if dropped_count > 0:
                    print(f"  ⚠ Queue drops: {dropped_count} packets")
                print_header()  # Re-print header after stats block

    # --- Main execution ---
    source_desc = args.interface or args.file
    mode = "live" if args.interface else "pcap"
    print(f"\n🔍 NetSight v{VERSION} — BACnet/IP Traffic Analyzer")
    print(f"   Mode: {mode} | Source: {source_desc}")
    if args.save:
        print(f"   Saving to: {args.save}")
    print_header()

    try:
        # Start capture transport
        await transport.start()

        # Run consumer + stats printer concurrently
        consumer_task = asyncio.create_task(consume_packets())
        stats_task = asyncio.create_task(print_periodic_stats())

        # Wait for shutdown signal or pcap replay completion
        if args.file:
            # For pcap replay: wait until replay finishes, then process remaining queue
            while transport.is_running:
                await asyncio.sleep(0.1)
            # Give the consumer time to drain the queue
            await asyncio.sleep(0.5)
            shutdown_event.set()
        else:
            # For live capture: wait for Ctrl+C / SIGTERM
            await shutdown_event.wait()

        # Stop capture
        await transport.stop()

        # Wait for consumer to finish draining
        await asyncio.wait_for(consumer_task, timeout=5.0)
        stats_task.cancel()
        try:
            await stats_task
        except asyncio.CancelledError:
            pass

    except PermissionError as e:
        print(f"\n❌ {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"\n❌ {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        # Fallback if signal handler didn't fire
        shutdown_event.set()
        await transport.stop()
    finally:
        if jsonl_file:
            jsonl_file.close()

    # --- Final report ---
    report = format_final_report(traffic_stats, device_registry, anomaly_detector)
    print(report)

    if dropped_count > 0:
        print(f"\n  ⚠ Total queue drops: {dropped_count} packets")
    if args.save:
        print(f"\n  📁 Saved {packet_count} packets to {args.save}")


# ---------------------------------------------------------------------------
# Utility commands
# ---------------------------------------------------------------------------

def list_interfaces() -> None:
    """Print available network interfaces and exit."""
    print("\nAvailable Network Interfaces:")
    print(f"  {'Name':<20} {'IP Address':<18} {'Description'}")
    print("  " + "─" * 60)

    interfaces = BACnetIPCapture.list_interfaces()
    if not interfaces:
        print("  (no interfaces found)")
        return

    for iface in interfaces:
        name = iface["name"]
        ip = iface.get("ip", "")
        desc = iface.get("description", "")
        print(f"  {name:<20} {ip:<18} {desc}")

    print()


# ---------------------------------------------------------------------------
# TUI mode
# ---------------------------------------------------------------------------

def run_tui(args: argparse.Namespace) -> None:
    """Launch the Textual TUI dashboard."""
    from backend.tui.app import NetSightApp

    # Load settings
    settings = load_settings(args.settings) if args.settings else load_settings()

    is_live = bool(args.interface)

    if is_live:
        transport = BACnetIPCapture(interface=args.interface)
    else:
        transport = PcapReplayCapture(
            file_path=args.file,
            replay_speed=args.replay_speed,
        )

    source_name = args.interface or args.file

    app = NetSightApp(
        transport,
        is_live=is_live,
        source_name=source_name,
        max_rows=args.tui_packets,
        save_path=args.save,
        replay_speed=args.replay_speed,
        settings=settings,
    )
    app.run()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Handle utility commands
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    # Require a capture source unless a utility command was used
    if not args.interface and not args.file:
        parser.error("one of the arguments -i/--interface -f/--file is required")

    # Serve mode stub
    if args.serve:
        print("⚠  --serve mode is not yet implemented (Phase 6).")
        print("   For now, use live capture or pcap replay in terminal mode.")
        sys.exit(0)

    # Dispatch: TUI (default) vs plain (scrolling terminal)
    if args.plain:
        # Original scrolling terminal output
        try:
            asyncio.run(run_capture(args))
        except KeyboardInterrupt:
            print("\nCapture interrupted.")
    else:
        # Textual TUI dashboard (default)
        try:
            run_tui(args)
        except KeyboardInterrupt:
            print("\nCapture interrupted.")


if __name__ == "__main__":
    main()
