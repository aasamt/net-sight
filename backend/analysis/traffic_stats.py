"""Traffic statistics — global and per-dimension counters with sliding window rates.

Accumulates packet/byte counts across multiple dimensions:
- Global totals and rates (1s, 10s, 60s sliding windows)
- Per-device (by effective source IP)
- Per-service (by APDU service name)
- Per-BVLC function
- Per-network priority
- Confirmed vs unconfirmed ratio
- Error/reject/abort counts

Thread-safe: all public methods can be called from async consumer or capture thread.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock

from backend.models.packet import ParsedPacket

logger = logging.getLogger(__name__)


@dataclass
class _TimestampedCount:
    """A count with its timestamp for sliding window rate calculation."""

    timestamp: float
    count: int = 1
    bytes: int = 0


@dataclass
class DimensionStats:
    """Counters for a single dimension value (e.g., one service type)."""

    name: str
    packet_count: int = 0
    byte_count: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
        }


class TrafficStats:
    """Accumulates traffic statistics from parsed packets.

    Usage:
        stats = TrafficStats()
        stats.process_packet(parsed_packet)  # Call for every packet
        summary = stats.get_summary()         # Snapshot of all stats
    """

    def __init__(self) -> None:
        self._lock = Lock()

        # Global counters
        self._total_packets: int = 0
        self._total_bytes: int = 0
        self._start_time: float | None = None
        self._last_packet_time: float | None = None

        # Sliding window for rate calculation (stores (timestamp, byte_count) tuples)
        self._recent_packets: deque[_TimestampedCount] = deque()

        # Per-dimension counters
        self._by_source_ip: dict[str, DimensionStats] = {}
        self._by_service: dict[str, DimensionStats] = {}
        self._by_bvlc_function: dict[str, DimensionStats] = {}
        self._by_priority: dict[str, DimensionStats] = {}

        # Confirmed vs unconfirmed
        self._confirmed_count: int = 0
        self._unconfirmed_count: int = 0

        # Error/reject/abort
        self._error_count: int = 0
        self._reject_count: int = 0
        self._abort_count: int = 0

    def process_packet(self, packet: ParsedPacket) -> None:
        """Process a parsed packet to update all statistics."""
        with self._lock:
            now = packet.timestamp

            # Global counters
            self._total_packets += 1
            self._total_bytes += packet.length
            if self._start_time is None:
                self._start_time = now
            self._last_packet_time = now

            # Sliding window entry
            self._recent_packets.append(
                _TimestampedCount(timestamp=now, bytes=packet.length)
            )
            # Prune entries older than 60 seconds
            cutoff = now - 60.0
            while self._recent_packets and self._recent_packets[0].timestamp < cutoff:
                self._recent_packets.popleft()

            # Per source IP
            src_ip = packet.effective_source_ip
            self._increment_dim(self._by_source_ip, src_ip, packet.length)

            # Per BVLC function
            if packet.bvlc:
                bvlc_name = packet.bvlc.function_name
                self._increment_dim(self._by_bvlc_function, bvlc_name, packet.length)

            # Per network priority
            if packet.npdu:
                priority_name = packet.npdu.priority_name
                self._increment_dim(self._by_priority, priority_name, packet.length)

            # Per APDU service + confirmed/unconfirmed tracking
            if packet.apdu:
                service = packet.apdu.service_name or f"PDU-Type-{packet.apdu.pdu_type}"
                self._increment_dim(self._by_service, service, packet.length)

                # Confirmed vs unconfirmed (only for request types 0 and 1)
                if packet.apdu.pdu_type == 0:
                    self._confirmed_count += 1
                elif packet.apdu.pdu_type == 1:
                    self._unconfirmed_count += 1

                # Error/reject/abort
                if packet.apdu.pdu_type == 5:
                    self._error_count += 1
                elif packet.apdu.pdu_type == 6:
                    self._reject_count += 1
                elif packet.apdu.pdu_type == 7:
                    self._abort_count += 1

    @staticmethod
    def _increment_dim(
        dim: dict[str, DimensionStats], key: str, byte_count: int
    ) -> None:
        """Increment a dimension counter, creating entry if needed."""
        if key not in dim:
            dim[key] = DimensionStats(name=key)
        dim[key].packet_count += 1
        dim[key].byte_count += byte_count

    def _calc_rate(self, window_seconds: float) -> tuple[float, float]:
        """Calculate packet rate (pps) and byte rate (Bps) over a time window.

        Returns (packets_per_second, bytes_per_second).
        """
        if not self._recent_packets or self._last_packet_time is None:
            return 0.0, 0.0

        cutoff = self._last_packet_time - window_seconds
        packets = 0
        total_bytes = 0
        for entry in self._recent_packets:
            if entry.timestamp >= cutoff:
                packets += entry.count
                total_bytes += entry.bytes

        if window_seconds <= 0:
            return 0.0, 0.0

        return packets / window_seconds, total_bytes / window_seconds

    def get_rates(self) -> dict[str, dict[str, float]]:
        """Get packet and byte rates for 1s, 10s, and 60s windows."""
        with self._lock:
            r1_pps, r1_bps = self._calc_rate(1.0)
            r10_pps, r10_bps = self._calc_rate(10.0)
            r60_pps, r60_bps = self._calc_rate(60.0)
            return {
                "1s": {"pps": round(r1_pps, 1), "bps": round(r1_bps, 1)},
                "10s": {"pps": round(r10_pps, 1), "bps": round(r10_bps, 1)},
                "60s": {"pps": round(r60_pps, 1), "bps": round(r60_bps, 1)},
            }

    def get_top_talkers(self, n: int = 10) -> list[dict]:
        """Get the top N source IPs by packet count."""
        with self._lock:
            sorted_ips = sorted(
                self._by_source_ip.values(),
                key=lambda d: d.packet_count,
                reverse=True,
            )
            return [
                {
                    "ip": d.name,
                    "packet_count": d.packet_count,
                    "byte_count": d.byte_count,
                    "percent": round(d.packet_count / max(self._total_packets, 1) * 100, 1),
                }
                for d in sorted_ips[:n]
            ]

    def get_service_breakdown(self) -> list[dict]:
        """Get packet counts broken down by APDU service type."""
        with self._lock:
            return sorted(
                [d.to_dict() for d in self._by_service.values()],
                key=lambda d: d["packet_count"],
                reverse=True,
            )

    def get_bvlc_breakdown(self) -> list[dict]:
        """Get packet counts broken down by BVLC function type."""
        with self._lock:
            return sorted(
                [d.to_dict() for d in self._by_bvlc_function.values()],
                key=lambda d: d["packet_count"],
                reverse=True,
            )

    def get_priority_breakdown(self) -> list[dict]:
        """Get packet counts broken down by network priority."""
        with self._lock:
            return sorted(
                [d.to_dict() for d in self._by_priority.values()],
                key=lambda d: d["packet_count"],
                reverse=True,
            )

    def get_summary(self) -> dict:
        """Get a full statistics summary snapshot."""
        with self._lock:
            duration = 0.0
            if self._start_time and self._last_packet_time:
                duration = self._last_packet_time - self._start_time

            total_requests = self._confirmed_count + self._unconfirmed_count

            return {
                "total_packets": self._total_packets,
                "total_bytes": self._total_bytes,
                "duration_seconds": round(duration, 2),
                "confirmed_count": self._confirmed_count,
                "unconfirmed_count": self._unconfirmed_count,
                "confirmed_ratio": (
                    round(self._confirmed_count / total_requests, 3)
                    if total_requests > 0
                    else 0.0
                ),
                "error_count": self._error_count,
                "reject_count": self._reject_count,
                "abort_count": self._abort_count,
            }

    @property
    def total_packets(self) -> int:
        with self._lock:
            return self._total_packets

    @property
    def total_bytes(self) -> int:
        with self._lock:
            return self._total_bytes

    def reset(self) -> None:
        """Clear all statistics. Used when starting a new capture session."""
        with self._lock:
            self._total_packets = 0
            self._total_bytes = 0
            self._start_time = None
            self._last_packet_time = None
            self._recent_packets.clear()
            self._by_source_ip.clear()
            self._by_service.clear()
            self._by_bvlc_function.clear()
            self._by_priority.clear()
            self._confirmed_count = 0
            self._unconfirmed_count = 0
            self._error_count = 0
            self._reject_count = 0
            self._abort_count = 0
