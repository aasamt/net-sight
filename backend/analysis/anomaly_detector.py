"""Anomaly detector — threshold-based alerting for BACnet network issues.

Detects operational anomalies by monitoring packet rates and patterns:
- Chatty device: source IP exceeding configurable pps threshold
- Broadcast storm: Who-Is/I-Am flood rate exceeding threshold
- Error/reject/abort rate: rising failure rates
- Routing issues: Reject-Message-To-Network occurrences
- Foreign device registration failures: BVLC-Result NAKs

Each anomaly is timestamped and categorized. Active anomalies can be queried
for display in terminal output or WebSocket streaming.

Thread-safe: all public methods can be called from async consumer or capture thread.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock

from backend.models.packet import ParsedPacket

logger = logging.getLogger(__name__)


class AnomalyType(str, Enum):
    """Categories of detectable anomalies."""

    CHATTY_DEVICE = "chatty-device"
    BROADCAST_STORM = "broadcast-storm"
    HIGH_ERROR_RATE = "high-error-rate"
    HIGH_REJECT_RATE = "high-reject-rate"
    HIGH_ABORT_RATE = "high-abort-rate"
    ROUTING_ISSUE = "routing-issue"
    FOREIGN_DEVICE_NAK = "foreign-device-nak"


@dataclass
class Anomaly:
    """A detected anomaly event."""

    type: AnomalyType
    message: str
    timestamp: float
    source_ip: str | None = None
    severity: str = "warning"  # "info", "warning", "critical"
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "message": self.message,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "severity": self.severity,
            "details": self.details,
        }


@dataclass
class _RateWindow:
    """Sliding window counter for rate-based detection."""

    timestamps: deque = field(default_factory=lambda: deque())
    window_seconds: float = 10.0

    def add(self, ts: float) -> None:
        self.timestamps.append(ts)
        cutoff = ts - self.window_seconds
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.popleft()

    @property
    def rate(self) -> float:
        """Current rate (events per second) over the window."""
        if len(self.timestamps) < 2:
            return 0.0
        return len(self.timestamps) / self.window_seconds


class AnomalyDetector:
    """Monitors parsed packets for operational anomalies.

    Configurable thresholds control sensitivity. Detected anomalies are
    stored in a capped list and can be queried for display.

    Usage:
        detector = AnomalyDetector(chatty_pps=50, broadcast_pps=30)
        detector.process_packet(parsed_packet)
        anomalies = detector.get_recent_anomalies()
    """

    def __init__(
        self,
        *,
        chatty_pps: float = 50.0,
        broadcast_pps: float = 30.0,
        error_pps: float = 10.0,
        reject_pps: float = 5.0,
        abort_pps: float = 5.0,
        window_seconds: float = 10.0,
        max_anomalies: int = 500,
        cooldown_seconds: float = 30.0,
    ) -> None:
        """Initialize the anomaly detector.

        Args:
            chatty_pps: Packets/sec threshold per source IP to flag as chatty.
            broadcast_pps: Who-Is + I-Am packets/sec threshold for broadcast storm.
            error_pps: Error PDUs/sec threshold.
            reject_pps: Reject PDUs/sec threshold.
            abort_pps: Abort PDUs/sec threshold.
            window_seconds: Sliding window duration for rate calculations.
            max_anomalies: Maximum number of anomalies to retain.
            cooldown_seconds: Minimum time between duplicate anomaly alerts.
        """
        self._lock = Lock()

        # Thresholds
        self._chatty_pps = chatty_pps
        self._broadcast_pps = broadcast_pps
        self._error_pps = error_pps
        self._reject_pps = reject_pps
        self._abort_pps = abort_pps
        self._window_seconds = window_seconds
        self._cooldown_seconds = cooldown_seconds

        # Rate windows per source IP
        self._per_ip_rates: dict[str, _RateWindow] = {}

        # Global rate windows for broadcast/error/reject/abort
        self._broadcast_rate = _RateWindow(window_seconds=window_seconds)
        self._error_rate = _RateWindow(window_seconds=window_seconds)
        self._reject_rate = _RateWindow(window_seconds=window_seconds)
        self._abort_rate = _RateWindow(window_seconds=window_seconds)

        # Detected anomalies (capped deque)
        self._anomalies: deque[Anomaly] = deque(maxlen=max_anomalies)

        # Cooldown tracker: (anomaly_type, source_ip) → last alert timestamp
        self._last_alert: dict[tuple[str, str | None], float] = {}

    def process_packet(self, packet: ParsedPacket) -> list[Anomaly]:
        """Process a parsed packet and return any new anomalies detected.

        Returns:
            List of newly detected anomalies (may be empty).
        """
        new_anomalies: list[Anomaly] = []

        with self._lock:
            ts = packet.timestamp
            src_ip = packet.effective_source_ip

            # --- Per-IP rate tracking (chatty device) ---
            if src_ip not in self._per_ip_rates:
                self._per_ip_rates[src_ip] = _RateWindow(
                    window_seconds=self._window_seconds
                )
            self._per_ip_rates[src_ip].add(ts)

            ip_rate = self._per_ip_rates[src_ip].rate
            if ip_rate >= self._chatty_pps:
                a = self._maybe_alert(
                    AnomalyType.CHATTY_DEVICE,
                    f"Chatty device: {src_ip} at {ip_rate:.0f} pps",
                    ts,
                    source_ip=src_ip,
                    severity="warning",
                    details={"rate_pps": round(ip_rate, 1)},
                )
                if a:
                    new_anomalies.append(a)

            # --- Broadcast storm (Who-Is / I-Am) ---
            if packet.apdu and packet.apdu.pdu_type == 1:
                if packet.apdu.service_choice in (0, 8):  # I-Am=0, Who-Is=8
                    self._broadcast_rate.add(ts)
                    bc_rate = self._broadcast_rate.rate
                    if bc_rate >= self._broadcast_pps:
                        a = self._maybe_alert(
                            AnomalyType.BROADCAST_STORM,
                            f"Broadcast storm: Who-Is/I-Am at {bc_rate:.0f} pps",
                            ts,
                            severity="critical",
                            details={"rate_pps": round(bc_rate, 1)},
                        )
                        if a:
                            new_anomalies.append(a)

            # --- Error rate ---
            if packet.apdu and packet.apdu.pdu_type == 5:
                self._error_rate.add(ts)
                err_rate = self._error_rate.rate
                if err_rate >= self._error_pps:
                    a = self._maybe_alert(
                        AnomalyType.HIGH_ERROR_RATE,
                        f"High error rate: {err_rate:.0f} errors/sec",
                        ts,
                        severity="warning",
                        details={"rate_pps": round(err_rate, 1)},
                    )
                    if a:
                        new_anomalies.append(a)

            # --- Reject rate ---
            if packet.apdu and packet.apdu.pdu_type == 6:
                self._reject_rate.add(ts)
                rej_rate = self._reject_rate.rate
                if rej_rate >= self._reject_pps:
                    a = self._maybe_alert(
                        AnomalyType.HIGH_REJECT_RATE,
                        f"High reject rate: {rej_rate:.0f} rejects/sec",
                        ts,
                        severity="warning",
                        details={"rate_pps": round(rej_rate, 1)},
                    )
                    if a:
                        new_anomalies.append(a)

            # --- Abort rate ---
            if packet.apdu and packet.apdu.pdu_type == 7:
                self._abort_rate.add(ts)
                abt_rate = self._abort_rate.rate
                if abt_rate >= self._abort_pps:
                    a = self._maybe_alert(
                        AnomalyType.HIGH_ABORT_RATE,
                        f"High abort rate: {abt_rate:.0f} aborts/sec",
                        ts,
                        severity="warning",
                        details={"rate_pps": round(abt_rate, 1)},
                    )
                    if a:
                        new_anomalies.append(a)

            # --- Routing issue (Reject-Message-To-Network) ---
            if packet.npdu and packet.npdu.is_network_message:
                if packet.npdu.network_message_type == 0x03:
                    reason = packet.npdu.reject_reason_name or "unknown"
                    a = self._maybe_alert(
                        AnomalyType.ROUTING_ISSUE,
                        f"Routing issue: Reject-Message-To-Network ({reason}) from {src_ip}",
                        ts,
                        source_ip=src_ip,
                        severity="warning",
                        details={
                            "reject_reason": packet.npdu.reject_reason,
                            "reject_reason_name": reason,
                        },
                    )
                    if a:
                        new_anomalies.append(a)

            # --- Foreign device registration failure ---
            if packet.bvlc and packet.bvlc.function == 0x00:
                if packet.bvlc.result_code is not None and packet.bvlc.result_code != 0:
                    result_name = packet.bvlc.result_name or f"0x{packet.bvlc.result_code:04X}"
                    a = self._maybe_alert(
                        AnomalyType.FOREIGN_DEVICE_NAK,
                        f"BVLC NAK: {result_name} from {src_ip}",
                        ts,
                        source_ip=src_ip,
                        severity="info",
                        details={
                            "result_code": packet.bvlc.result_code,
                            "result_name": result_name,
                        },
                    )
                    if a:
                        new_anomalies.append(a)

        return new_anomalies

    def _maybe_alert(
        self,
        anomaly_type: AnomalyType,
        message: str,
        timestamp: float,
        source_ip: str | None = None,
        severity: str = "warning",
        details: dict | None = None,
    ) -> Anomaly | None:
        """Create an anomaly if cooldown period has elapsed for this type+source."""
        key = (anomaly_type.value, source_ip)
        last = self._last_alert.get(key, 0.0)
        if timestamp - last < self._cooldown_seconds:
            return None

        self._last_alert[key] = timestamp
        anomaly = Anomaly(
            type=anomaly_type,
            message=message,
            timestamp=timestamp,
            source_ip=source_ip,
            severity=severity,
            details=details or {},
        )
        self._anomalies.append(anomaly)
        logger.info("Anomaly detected: %s", message)
        return anomaly

    def get_recent_anomalies(self, limit: int = 50) -> list[Anomaly]:
        """Get the most recent anomalies."""
        with self._lock:
            items = list(self._anomalies)
            return items[-limit:]

    def get_anomaly_count(self) -> int:
        """Get the total number of stored anomalies."""
        with self._lock:
            return len(self._anomalies)

    def to_dict_list(self, limit: int = 50) -> list[dict]:
        """Serialize recent anomalies for JSON output."""
        return [a.to_dict() for a in self.get_recent_anomalies(limit)]

    def reset(self) -> None:
        """Clear all anomaly state. Used when starting a new capture session."""
        with self._lock:
            self._per_ip_rates.clear()
            self._broadcast_rate = _RateWindow(window_seconds=self._window_seconds)
            self._error_rate = _RateWindow(window_seconds=self._window_seconds)
            self._reject_rate = _RateWindow(window_seconds=self._window_seconds)
            self._abort_rate = _RateWindow(window_seconds=self._window_seconds)
            self._anomalies.clear()
            self._last_alert.clear()
