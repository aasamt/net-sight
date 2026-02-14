"""Phase 5 tests — CLI entry point, pipeline integration, output formatting."""

from __future__ import annotations

import asyncio
import json
import struct
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from backend.analysis.anomaly_detector import AnomalyDetector
from backend.analysis.device_registry import DeviceRegistry
from backend.analysis.traffic_stats import TrafficStats
from backend.main import (
    VERSION,
    build_parser,
    format_final_report,
    format_stats_block,
    list_interfaces,
    run_capture,
)
from backend.models.packet import ParsedPacket
from backend.parsers.pipeline import parse_packet
from backend.transport.base import RawPacket
from backend.transport.pcap_replay import PcapReplayCapture


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_iam_bytes(device_instance: int = 1234) -> bytes:
    """Build raw I-Am packet bytes (BVLC + NPDU + APDU)."""
    obj_id = struct.pack(">I", (8 << 22) | device_instance)
    bvlc = bytes([0x81, 0x0B, 0x00, 0x19])
    npdu = bytes([0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF])
    apdu = bytes([0x10, 0x00])
    apdu += bytes([0xC4]) + obj_id
    apdu += bytes([0x22, 0x01, 0xE0])
    apdu += bytes([0x91, 0x00])
    apdu += bytes([0x21, 0x03])
    return bvlc + npdu + apdu


def _make_whois_bytes() -> bytes:
    """Build raw Who-Is packet bytes."""
    bvlc = bytes([0x81, 0x0B, 0x00, 0x0C])
    npdu = bytes([0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF])
    apdu = bytes([0x10, 0x08])
    return bvlc + npdu + apdu


def _make_readprop_bytes() -> bytes:
    """Build raw ReadProperty request bytes."""
    bvlc = bytes([0x81, 0x0A, 0x00, 0x11])
    npdu = bytes([0x01, 0x04])
    apdu = bytes([0x00, 0x04, 0x01, 0x0C])
    apdu += bytes([0x0C]) + struct.pack(">I", (0 << 22) | 1)
    apdu += bytes([0x19, 0x55])
    return bvlc + npdu + apdu


def _make_raw_packet(
    raw_bytes: bytes,
    source_ip: str = "192.168.1.100",
    dest_ip: str = "192.168.1.255",
    timestamp: float = 1700000000.0,
) -> RawPacket:
    """Build a RawPacket from raw bytes."""
    return RawPacket(
        timestamp=timestamp,
        raw_bytes=raw_bytes,
        source_ip=source_ip,
        source_port=47808,
        destination_ip=dest_ip,
        destination_port=47808,
        length=len(raw_bytes) + 42,  # ~Ethernet+IP+UDP overhead
    )


def _make_test_pcap(path: Path) -> None:
    """Create a minimal test pcap file with BACnet packets."""
    from scapy.all import IP, UDP, Ether, Raw, wrpcap

    packets = []
    defs = [
        (_make_iam_bytes(1234), "192.168.1.100", "192.168.1.255"),
        (_make_readprop_bytes(), "192.168.1.50", "192.168.1.100"),
        (_make_whois_bytes(), "192.168.1.50", "192.168.1.255"),
        (_make_iam_bytes(5678), "192.168.1.101", "192.168.1.255"),
        (_make_readprop_bytes(), "192.168.1.50", "192.168.1.101"),
    ]
    for i, (payload, src, dst) in enumerate(defs):
        pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=47808, dport=47808) / Raw(load=payload)
        pkt.time = 1700000000.0 + i * 0.5
        packets.append(pkt)
    wrpcap(str(path), packets)


# ===========================================================================
# Group 1: Argument parsing
# ===========================================================================


class TestArgParsing:
    """Verify argparse setup and mutual exclusion."""

    def test_interface_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-i", "en0"])
        assert args.interface == "en0"
        assert args.file is None

    def test_file_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", "capture.pcap"])
        assert args.file == "capture.pcap"
        assert args.interface is None

    def test_mutual_exclusion(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["-i", "en0", "-f", "capture.pcap"])

    def test_save_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", "test.pcap", "-o", "output.jsonl"])
        assert args.save == "output.jsonl"

    def test_stats_interval_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-i", "en0"])
        assert args.stats_interval == 10

    def test_stats_interval_custom(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-i", "en0", "--stats-interval", "5"])
        assert args.stats_interval == 5

    def test_stats_interval_disabled(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-i", "en0", "--stats-interval", "0"])
        assert args.stats_interval == 0

    def test_replay_speed_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", "test.pcap"])
        assert args.replay_speed == 0.0

    def test_replay_speed_custom(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", "test.pcap", "--replay-speed", "2.0"])
        assert args.replay_speed == 2.0

    def test_verbose_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-i", "en0", "-v"])
        assert args.verbose is True

    def test_quiet_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-i", "en0", "-q"])
        assert args.quiet is True

    def test_serve_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-i", "en0", "--serve"])
        assert args.serve is True

    def test_list_interfaces_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--list-interfaces"])
        assert args.list_interfaces is True

    def test_version_flag(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0


# ===========================================================================
# Group 2: Output formatting
# ===========================================================================


class TestOutputFormatting:
    """Verify stats block and final report formatting."""

    def _make_engines_with_packets(self) -> tuple[TrafficStats, DeviceRegistry, AnomalyDetector]:
        """Create analysis engines fed with sample packets."""
        stats = TrafficStats()
        registry = DeviceRegistry()
        detector = AnomalyDetector()

        packets = [
            _make_raw_packet(_make_iam_bytes(1234), "192.168.1.100"),
            _make_raw_packet(_make_readprop_bytes(), "192.168.1.50", "192.168.1.100"),
            _make_raw_packet(_make_whois_bytes(), "192.168.1.50"),
            _make_raw_packet(_make_iam_bytes(5678), "192.168.1.101", timestamp=1700000001.0),
            _make_raw_packet(_make_readprop_bytes(), "192.168.1.50", "192.168.1.101",
                             timestamp=1700000001.5),
        ]

        for raw in packets:
            parsed = parse_packet(raw)
            stats.process_packet(parsed)
            registry.process_packet(parsed)
            detector.process_packet(parsed)

        return stats, registry, detector

    def test_stats_block_contains_key_info(self) -> None:
        stats, registry, detector = self._make_engines_with_packets()
        block = format_stats_block(stats, registry, detector)

        assert "TRAFFIC STATISTICS" in block
        assert "Packets:" in block
        assert "Bytes:" in block
        assert "Rate" in block
        assert "Devices discovered:" in block

    def test_stats_block_shows_top_talkers(self) -> None:
        stats, registry, detector = self._make_engines_with_packets()
        block = format_stats_block(stats, registry, detector)
        assert "TOP TALKERS" in block
        assert "192.168.1.50" in block

    def test_final_report_contains_sections(self) -> None:
        stats, registry, detector = self._make_engines_with_packets()
        report = format_final_report(stats, registry, detector)

        assert "FINAL REPORT" in report
        assert "Total packets:" in report
        assert "Devices discovered:" in report
        assert "Top Talkers:" in report
        assert "Service Breakdown:" in report

    def test_final_report_device_details(self) -> None:
        stats, registry, detector = self._make_engines_with_packets()
        report = format_final_report(stats, registry, detector)

        assert "Device:1234" in report
        assert "Device:5678" in report
        assert "192.168.1.100" in report
        assert "192.168.1.101" in report

    def test_final_report_service_breakdown(self) -> None:
        stats, registry, detector = self._make_engines_with_packets()
        report = format_final_report(stats, registry, detector)

        assert "I-Am" in report
        assert "ReadProperty" in report
        assert "Who-Is" in report

    def test_final_report_packet_counts(self) -> None:
        stats, registry, detector = self._make_engines_with_packets()
        report = format_final_report(stats, registry, detector)

        assert "Total packets:   5" in report
        assert "Confirmed:       2" in report
        assert "Unconfirmed:     3" in report

    def test_empty_engines_no_crash(self) -> None:
        """Empty engines should still produce valid output without crashing."""
        stats = TrafficStats()
        registry = DeviceRegistry()
        detector = AnomalyDetector()

        block = format_stats_block(stats, registry, detector)
        assert "TRAFFIC STATISTICS" in block

        report = format_final_report(stats, registry, detector)
        assert "FINAL REPORT" in report
        assert "Total packets:   0" in report


# ===========================================================================
# Group 3: Pipeline integration (pcap replay)
# ===========================================================================


class TestPcapPipeline:
    """End-to-end pipeline tests using pcap replay."""

    @pytest.fixture
    def pcap_file(self, tmp_path: Path) -> Path:
        """Create a temporary test pcap file."""
        pcap_path = tmp_path / "test.pcap"
        _make_test_pcap(pcap_path)
        return pcap_path

    @pytest.mark.asyncio
    async def test_pcap_replay_pipeline(self, pcap_file: Path) -> None:
        """Full pipeline: pcap → queue → parse → analyze."""
        loop = asyncio.get_running_loop()

        registry = DeviceRegistry()
        stats = TrafficStats()
        detector = AnomalyDetector()

        queue: asyncio.Queue[RawPacket] = asyncio.Queue(maxsize=10_000)

        def enqueue(raw: RawPacket) -> None:
            try:
                queue.put_nowait(raw)
            except asyncio.QueueFull:
                pass

        transport = PcapReplayCapture(file_path=pcap_file, replay_speed=0.0)
        transport.on_packet(enqueue)

        await transport.start()

        # Wait for replay to finish
        while transport.is_running:
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.2)

        # Drain queue
        packet_count = 0
        while not queue.empty():
            raw = queue.get_nowait()
            parsed = parse_packet(raw)
            registry.process_packet(parsed)
            stats.process_packet(parsed)
            detector.process_packet(parsed)
            packet_count += 1

        assert packet_count == 5
        assert stats.total_packets == 5
        assert registry.get_device_count() == 2

        summary = stats.get_summary()
        assert summary["confirmed_count"] == 2
        assert summary["unconfirmed_count"] == 3

    @pytest.mark.asyncio
    async def test_pcap_replay_with_jsonl_output(self, pcap_file: Path, tmp_path: Path) -> None:
        """Test JSONL output from pcap replay."""
        jsonl_path = tmp_path / "output.jsonl"

        queue: asyncio.Queue[RawPacket] = asyncio.Queue(maxsize=10_000)

        def enqueue(raw: RawPacket) -> None:
            try:
                queue.put_nowait(raw)
            except asyncio.QueueFull:
                pass

        transport = PcapReplayCapture(file_path=pcap_file, replay_speed=0.0)
        transport.on_packet(enqueue)

        await transport.start()
        while transport.is_running:
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.2)

        # Process and write JSONL
        with open(jsonl_path, "w") as f:
            while not queue.empty():
                raw = queue.get_nowait()
                parsed = parse_packet(raw)
                f.write(parsed.model_dump_json() + "\n")

        # Validate JSONL
        lines = jsonl_path.read_text().strip().split("\n")
        assert len(lines) == 5

        for line in lines:
            obj = json.loads(line)
            assert "id" in obj
            assert "timestamp" in obj
            assert "bvlc" in obj
            assert "source_ip" in obj

        # Verify first packet is I-Am from 192.168.1.100
        first = json.loads(lines[0])
        assert first["source_ip"] == "192.168.1.100"
        assert first["bvlc"]["function_name"] == "Original-Broadcast-NPDU"
        assert first["apdu"]["service_name"] == "I-Am"

    @pytest.mark.asyncio
    async def test_queue_drop_on_overflow(self) -> None:
        """Verify that QueueFull is handled gracefully (drop, don't block)."""
        queue: asyncio.Queue[RawPacket] = asyncio.Queue(maxsize=2)
        dropped = 0

        def enqueue(raw: RawPacket) -> None:
            nonlocal dropped
            try:
                queue.put_nowait(raw)
            except asyncio.QueueFull:
                dropped += 1

        raw = _make_raw_packet(_make_iam_bytes())

        # Fill the queue
        enqueue(raw)
        enqueue(raw)
        assert queue.qsize() == 2

        # This should drop, not block
        enqueue(raw)
        assert dropped == 1
        assert queue.qsize() == 2


# ===========================================================================
# Group 4: run_capture integration (argparse namespace → full pipeline)
# ===========================================================================


class TestRunCapture:
    """Test the run_capture function with mock args."""

    @pytest.fixture
    def pcap_file(self, tmp_path: Path) -> Path:
        pcap_path = tmp_path / "test.pcap"
        _make_test_pcap(pcap_path)
        return pcap_path

    @pytest.mark.asyncio
    async def test_run_capture_pcap_mode(self, pcap_file: Path, capsys: pytest.CaptureFixture) -> None:
        """run_capture with a pcap file should parse all packets and print a report."""
        parser = build_parser()
        args = parser.parse_args(["-f", str(pcap_file), "--stats-interval", "0"])

        await run_capture(args)

        captured = capsys.readouterr()
        assert "NetSight" in captured.out
        assert "FINAL REPORT" in captured.out
        assert "Total packets:   5" in captured.out
        assert "Device:1234" in captured.out
        assert "Device:5678" in captured.out

    @pytest.mark.asyncio
    async def test_run_capture_quiet_mode(self, pcap_file: Path, capsys: pytest.CaptureFixture) -> None:
        """Quiet mode should suppress per-packet output."""
        parser = build_parser()
        args = parser.parse_args(["-f", str(pcap_file), "--stats-interval", "0", "-q"])

        await run_capture(args)

        captured = capsys.readouterr()
        # Per-packet lines start with #
        packet_lines = [l for l in captured.out.split("\n") if l.strip().startswith("#") and "→" in l]
        assert len(packet_lines) == 0
        # But final report should still be there
        assert "FINAL REPORT" in captured.out

    @pytest.mark.asyncio
    async def test_run_capture_with_save(self, pcap_file: Path, tmp_path: Path) -> None:
        """run_capture with --save should create a JSONL file."""
        jsonl_path = tmp_path / "saved.jsonl"
        parser = build_parser()
        args = parser.parse_args([
            "-f", str(pcap_file), "--stats-interval", "0", "-o", str(jsonl_path),
        ])

        await run_capture(args)

        assert jsonl_path.exists()
        lines = jsonl_path.read_text().strip().split("\n")
        assert len(lines) == 5

    @pytest.mark.asyncio
    async def test_run_capture_file_not_found(self) -> None:
        """run_capture with non-existent file should exit cleanly."""
        parser = build_parser()
        args = parser.parse_args(["-f", "/nonexistent/file.pcap", "--stats-interval", "0"])

        with pytest.raises(SystemExit) as exc_info:
            await run_capture(args)
        assert exc_info.value.code == 1


# ===========================================================================
# Group 5: ParsedPacket.summary format
# ===========================================================================


class TestPacketSummary:
    """Verify the one-line summary format used for terminal output."""

    def test_iam_summary(self) -> None:
        raw = _make_raw_packet(_make_iam_bytes())
        parsed = parse_packet(raw)
        summary = parsed.summary

        assert f"#{parsed.id}" in summary
        assert "192.168.1.100" in summary
        assert "Original-Broadcast-NPDU" in summary
        assert "I-Am" in summary

    def test_readprop_summary(self) -> None:
        raw = _make_raw_packet(_make_readprop_bytes(), "192.168.1.50", "192.168.1.100")
        parsed = parse_packet(raw)
        summary = parsed.summary

        assert "192.168.1.50" in summary
        assert "ReadProperty" in summary
        assert "Original-Unicast-NPDU" in summary

    def test_whois_summary(self) -> None:
        raw = _make_raw_packet(_make_whois_bytes(), "192.168.1.50")
        parsed = parse_packet(raw)
        summary = parsed.summary

        assert "Who-Is" in summary

    def test_summary_includes_size(self) -> None:
        raw = _make_raw_packet(_make_iam_bytes())
        parsed = parse_packet(raw)
        summary = parsed.summary
        # Summary ends with size in bytes
        assert "B" in summary


# ===========================================================================
# Group 6: list_interfaces
# ===========================================================================


class TestListInterfaces:
    """Verify interface listing output."""

    def test_list_interfaces_output(self, capsys: pytest.CaptureFixture) -> None:
        list_interfaces()
        captured = capsys.readouterr()
        assert "Available Network Interfaces" in captured.out
        assert "Name" in captured.out
        assert "IP Address" in captured.out


# ===========================================================================
# Group 7: Version constant
# ===========================================================================


class TestVersion:
    """Verify version constant."""

    def test_version_format(self) -> None:
        parts = VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_version_value(self) -> None:
        assert VERSION == "0.1.0"
