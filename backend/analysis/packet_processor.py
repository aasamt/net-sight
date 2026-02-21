"""Shared packet processing pipeline — parse → analyze → extract display fields.

Eliminates duplication between the plain-mode CLI runner (main.py) and the
TUI app (app.py) by owning the analysis engines and providing a unified
`process()` method.

Usage:
    processor = PacketProcessor(settings=settings)
    result = processor.process(raw_packet)
    # result.parsed, result.anomalies, result.service, result.pdu_type, result.obj_str
"""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.analysis.anomaly_detector import Anomaly, AnomalyDetector
from backend.analysis.device_registry import DeviceRegistry
from backend.analysis.traffic_stats import TrafficStats
from backend.models.packet import ParsedPacket
from backend.parsers.pipeline import parse_packet
from backend.settings import Settings, load_settings
from backend.transport.base import RawPacket


@dataclass
class ProcessedResult:
    """Result of processing a single raw packet through the pipeline."""

    parsed: ParsedPacket
    anomalies: list[Anomaly] = field(default_factory=list)
    service: str = ""
    pdu_type: str = ""
    obj_str: str = ""


class PacketProcessor:
    """Owns the analysis engines and provides a unified parse→analyze pipeline.

    Both plain-mode CLI and TUI consume this processor's output, eliminating
    the duplicated pipeline logic.
    """

    def __init__(self, *, settings: Settings | None = None) -> None:
        self._settings = settings if settings is not None else load_settings()

        # Analysis engines
        self.device_registry = DeviceRegistry()
        self.traffic_stats = TrafficStats()
        self.anomaly_detector = AnomalyDetector(**self._settings.anomaly_kwargs())

    @property
    def settings(self) -> Settings:
        """The settings object used by this processor."""
        return self._settings

    def process(self, raw: RawPacket) -> ProcessedResult:
        """Parse a raw packet, feed analysis engines, extract display fields.

        Args:
            raw: The raw packet from the transport layer.

        Returns:
            ProcessedResult with parsed packet, anomalies, and display fields.
        """
        parsed = parse_packet(raw)

        # Feed analysis engines
        self.device_registry.process_packet(parsed)
        self.traffic_stats.process_packet(parsed)
        anomalies = self.anomaly_detector.process_packet(parsed)

        # Extract display fields (shared logic, previously duplicated)
        service = _extract_service(parsed)
        pdu_type = _extract_pdu_type(parsed)
        obj_str = _extract_obj_str(parsed)

        return ProcessedResult(
            parsed=parsed,
            anomalies=anomalies,
            service=service,
            pdu_type=pdu_type,
            obj_str=obj_str,
        )


def _extract_service(parsed: ParsedPacket) -> str:
    """Extract the best service name from a parsed packet."""
    if parsed.apdu and parsed.apdu.service_name:
        return parsed.apdu.service_name
    if parsed.npdu and parsed.npdu.network_message_name:
        return parsed.npdu.network_message_name
    if parsed.bvlc:
        return parsed.bvlc.function_name
    return ""


def _extract_pdu_type(parsed: ParsedPacket) -> str:
    """Extract the best PDU type name from a parsed packet."""
    if parsed.apdu:
        return parsed.apdu.pdu_type_name
    if parsed.npdu and parsed.npdu.is_network_message:
        return "Network"
    if parsed.bvlc:
        return parsed.bvlc.function_name
    return ""


def _extract_obj_str(parsed: ParsedPacket) -> str:
    """Extract formatted object identifier string from a parsed packet."""
    if parsed.apdu and parsed.apdu.object_identifier:
        oid = parsed.apdu.object_identifier
        return f"{oid.object_type_name}-{oid.instance}"
    return ""
