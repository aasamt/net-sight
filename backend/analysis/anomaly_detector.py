"""Anomaly detector — threshold-based alerting for BACnet network issues.

Detects operational anomalies by monitoring packet rates and patterns:
- Chatty device: source IP exceeding configurable pps threshold
- Broadcast storm: multi-pattern detection across 4 sub-types:
    • Discovery flood: Who-Is/I-Am/Who-Has/I-Have
    • Time sync flood: TimeSynchronization/UTC-TimeSynchronization
    • Unconfirmed service flood: UnconfirmedCOVNotification/WriteGroup
    • Router discovery flood: Who-Is-Router/I-Am-Router (NPDU network messages)
  Plus an aggregate rate across all broadcast-type traffic.
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

# ---------------------------------------------------------------------------
# BACnet protocol constants (avoid magic numbers in detection logic)
# ---------------------------------------------------------------------------

# APDU PDU types (upper nibble of first APDU byte)
PDU_TYPE_UNCONFIRMED_REQUEST = 1
PDU_TYPE_ERROR = 5
PDU_TYPE_REJECT = 6
PDU_TYPE_ABORT = 7

# Unconfirmed service choice codes
SVC_I_AM = 0
SVC_I_HAVE = 1
SVC_UNCONFIRMED_COV_NOTIFICATION = 2
SVC_TIME_SYNCHRONIZATION = 6
SVC_WHO_HAS = 7
SVC_WHO_IS = 8
SVC_UTC_TIME_SYNCHRONIZATION = 9
SVC_WRITE_GROUP = 10

# Unconfirmed service groups (sets used for multi-pattern matching)
DISCOVERY_SERVICES = frozenset({SVC_I_AM, SVC_I_HAVE, SVC_WHO_HAS, SVC_WHO_IS})
TIME_SYNC_SERVICES = frozenset({SVC_TIME_SYNCHRONIZATION, SVC_UTC_TIME_SYNCHRONIZATION})
UNCONFIRMED_FLOOD_SERVICES = frozenset({SVC_UNCONFIRMED_COV_NOTIFICATION, SVC_WRITE_GROUP})

# NPDU network layer message types
NET_MSG_WHO_IS_ROUTER = 0x00
NET_MSG_I_AM_ROUTER = 0x01
NET_MSG_REJECT_MESSAGE_TO_NETWORK = 0x03
ROUTER_DISCOVERY_MESSAGES = frozenset({NET_MSG_WHO_IS_ROUTER, NET_MSG_I_AM_ROUTER})

# BVLC function codes
BVLC_RESULT = 0x00

# BACnet object types
OBJECT_TYPE_DEVICE = 8

# NPDU addressing
GLOBAL_BROADCAST_NETWORK = 0xFFFF


class AnomalyType(str, Enum):
    """Categories of detectable anomalies."""

    CHATTY_DEVICE = "chatty-device"
    BROADCAST_STORM = "broadcast-storm"
    HIGH_ERROR_RATE = "high-error-rate"
    HIGH_REJECT_RATE = "high-reject-rate"
    HIGH_ABORT_RATE = "high-abort-rate"
    ROUTING_ISSUE = "routing-issue"
    FOREIGN_DEVICE_NAK = "foreign-device-nak"
    DUPLICATE_DEVICE_ID = "duplicate-device-id"


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


@dataclass
class _BroadcastCheck:
    """Descriptor for a broadcast storm sub-type rate check."""

    storm_type: str
    rate_window: _RateWindow
    threshold: float
    message_template: str  # formatted with {rate:.0f}


@dataclass
class _PduRateCheck:
    """Descriptor for a PDU-type rate check (error/reject/abort)."""

    anomaly_type: AnomalyType
    pdu_type: int
    rate_window: _RateWindow
    threshold: float
    message_template: str  # formatted with {rate:.0f}
    severity: str = "warning"


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
        timesync_pps: float = 10.0,
        unconfirmed_flood_pps: float = 30.0,
        router_discovery_pps: float = 20.0,
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
            broadcast_pps: Aggregate broadcast pps threshold (also used for
                discovery sub-type: Who-Is/I-Am/Who-Has/I-Have).
            timesync_pps: TimeSynchronization/UTC-TimeSynchronization pps threshold.
            unconfirmed_flood_pps: UnconfirmedCOVNotification/WriteGroup pps threshold.
            router_discovery_pps: Who-Is-Router/I-Am-Router (NPDU) pps threshold.
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
        self._timesync_pps = timesync_pps
        self._unconfirmed_flood_pps = unconfirmed_flood_pps
        self._router_discovery_pps = router_discovery_pps
        self._error_pps = error_pps
        self._reject_pps = reject_pps
        self._abort_pps = abort_pps
        self._window_seconds = window_seconds
        self._cooldown_seconds = cooldown_seconds

        # Rate windows per source IP
        self._per_ip_rates: dict[str, _RateWindow] = {}

        # Broadcast sub-type rate windows
        self._discovery_rate = _RateWindow(window_seconds=window_seconds)
        self._timesync_rate = _RateWindow(window_seconds=window_seconds)
        self._unconfirmed_flood_rate = _RateWindow(window_seconds=window_seconds)
        self._router_discovery_rate = _RateWindow(window_seconds=window_seconds)
        # Aggregate broadcast rate (all sub-types combined)
        self._broadcast_rate = _RateWindow(window_seconds=window_seconds)

        # Broadcast storm check descriptors (storm_type → check)
        self._broadcast_checks: dict[str, _BroadcastCheck] = {
            "discovery": _BroadcastCheck(
                storm_type="discovery",
                rate_window=self._discovery_rate,
                threshold=self._broadcast_pps,
                message_template=(
                    "Broadcast storm: discovery flood"
                    " (Who-Is/I-Am/Who-Has/I-Have) at {rate:.0f} pps"
                ),
            ),
            "timesync": _BroadcastCheck(
                storm_type="timesync",
                rate_window=self._timesync_rate,
                threshold=self._timesync_pps,
                message_template="Broadcast storm: time sync flood at {rate:.0f} pps",
            ),
            "unconfirmed": _BroadcastCheck(
                storm_type="unconfirmed",
                rate_window=self._unconfirmed_flood_rate,
                threshold=self._unconfirmed_flood_pps,
                message_template=(
                    "Broadcast storm: unconfirmed service flood"
                    " (COV/WriteGroup) at {rate:.0f} pps"
                ),
            ),
            "router": _BroadcastCheck(
                storm_type="router",
                rate_window=self._router_discovery_rate,
                threshold=self._router_discovery_pps,
                message_template=(
                    "Broadcast storm: router discovery flood"
                    " ({msg_name}) at {rate:.0f} pps"
                ),
            ),
        }

        # Global rate windows for error/reject/abort
        self._error_rate = _RateWindow(window_seconds=window_seconds)
        self._reject_rate = _RateWindow(window_seconds=window_seconds)
        self._abort_rate = _RateWindow(window_seconds=window_seconds)

        # PDU type rate check descriptors
        self._pdu_rate_checks: list[_PduRateCheck] = [
            _PduRateCheck(
                anomaly_type=AnomalyType.HIGH_ERROR_RATE,
                pdu_type=PDU_TYPE_ERROR,
                rate_window=self._error_rate,
                threshold=self._error_pps,
                message_template="High error rate: {rate:.0f} errors/sec",
            ),
            _PduRateCheck(
                anomaly_type=AnomalyType.HIGH_REJECT_RATE,
                pdu_type=PDU_TYPE_REJECT,
                rate_window=self._reject_rate,
                threshold=self._reject_pps,
                message_template="High reject rate: {rate:.0f} rejects/sec",
            ),
            _PduRateCheck(
                anomaly_type=AnomalyType.HIGH_ABORT_RATE,
                pdu_type=PDU_TYPE_ABORT,
                rate_window=self._abort_rate,
                threshold=self._abort_pps,
                message_template="High abort rate: {rate:.0f} aborts/sec",
            ),
        ]

        # Detected anomalies (capped deque)
        self._anomalies: deque[Anomaly] = deque(maxlen=max_anomalies)

        # Cooldown tracker: (anomaly_type, source_ip, subkey) → last alert timestamp
        self._last_alert: dict[tuple[str, str | None, str | None], float] = {}

        # Duplicate device ID tracking: device instance → set of IPs
        self._instance_ips: dict[int, set[str]] = {}

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

            # --- Broadcast storm detection (multi-pattern) ---
            is_global_broadcast = (
                packet.npdu
                and packet.npdu.destination_network == GLOBAL_BROADCAST_NETWORK
            )

            # Classify packet into matching broadcast sub-types
            matched_storm_types: list[str] = []
            if packet.apdu and packet.apdu.pdu_type == PDU_TYPE_UNCONFIRMED_REQUEST:
                sc = packet.apdu.service_choice
                if sc in DISCOVERY_SERVICES:
                    matched_storm_types.append("discovery")
                if sc in TIME_SYNC_SERVICES:
                    matched_storm_types.append("timesync")
                if sc in UNCONFIRMED_FLOOD_SERVICES:
                    matched_storm_types.append("unconfirmed")
            if packet.npdu and packet.npdu.is_network_message:
                if packet.npdu.network_message_type in ROUTER_DISCOVERY_MESSAGES:
                    matched_storm_types.append("router")

            # Process matched broadcast sub-type checks
            for storm_type in matched_storm_types:
                check = self._broadcast_checks[storm_type]
                check.rate_window.add(ts)
                self._broadcast_rate.add(ts)
                rate = check.rate_window.rate
                if rate >= check.threshold:
                    # Build message (router check uses msg_name from packet)
                    msg_name = ""
                    if storm_type == "router":
                        msg_name = (
                            packet.npdu.network_message_name
                            if packet.npdu and packet.npdu.network_message_name
                            else "router-discovery"
                        )
                    message = check.message_template.format(rate=rate, msg_name=msg_name)
                    a = self._maybe_alert(
                        AnomalyType.BROADCAST_STORM,
                        message,
                        ts,
                        severity="critical",
                        details={
                            "storm_type": storm_type,
                            "rate_pps": round(rate, 1),
                            "global_broadcast": is_global_broadcast,
                        },
                        cooldown_subkey=storm_type,
                    )
                    if a:
                        new_anomalies.append(a)

            # Aggregate: total broadcast-type traffic exceeds threshold
            # (catches mixed storms that individually stay below sub-type thresholds)
            agg_rate = self._broadcast_rate.rate
            if agg_rate >= self._broadcast_pps:
                # Only alert if no sub-type alert was already raised in this call
                if not any(
                    a.type == AnomalyType.BROADCAST_STORM for a in new_anomalies
                ):
                    a = self._maybe_alert(
                        AnomalyType.BROADCAST_STORM,
                        f"Broadcast storm: aggregate broadcast traffic"
                        f" at {agg_rate:.0f} pps",
                        ts,
                        severity="critical",
                        details={
                            "storm_type": "aggregate",
                            "rate_pps": round(agg_rate, 1),
                            "global_broadcast": is_global_broadcast,
                        },
                        cooldown_subkey="aggregate",
                    )
                    if a:
                        new_anomalies.append(a)

            # --- PDU type rate checks (error/reject/abort) ---
            if packet.apdu:
                for check in self._pdu_rate_checks:
                    if packet.apdu.pdu_type == check.pdu_type:
                        check.rate_window.add(ts)
                        rate = check.rate_window.rate
                        if rate >= check.threshold:
                            message = check.message_template.format(rate=rate)
                            a = self._maybe_alert(
                                check.anomaly_type,
                                message,
                                ts,
                                severity=check.severity,
                                details={"rate_pps": round(rate, 1)},
                            )
                            if a:
                                new_anomalies.append(a)

            # --- Routing issue (Reject-Message-To-Network) ---
            if packet.npdu and packet.npdu.is_network_message:
                if packet.npdu.network_message_type == NET_MSG_REJECT_MESSAGE_TO_NETWORK:
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

            # --- Duplicate device ID (same instance from different IPs) ---
            # Any packet with a Device-type object identifier (type 8) associates
            # the source IP with that device instance. If two different IPs are
            # seen referencing the same Device instance, flag it.
            if packet.apdu and packet.apdu.object_identifier is not None:
                obj_id = packet.apdu.object_identifier
                if obj_id.object_type == OBJECT_TYPE_DEVICE:
                    instance = obj_id.instance
                    if instance not in self._instance_ips:
                        self._instance_ips[instance] = set()
                    self._instance_ips[instance].add(src_ip)
                    if len(self._instance_ips[instance]) > 1:
                        ips = sorted(self._instance_ips[instance])
                        a = self._maybe_alert(
                            AnomalyType.DUPLICATE_DEVICE_ID,
                            f"Duplicate Device ID: instance {instance} claimed by {', '.join(ips)}",
                            ts,
                            source_ip=src_ip,
                            severity="critical",
                            details={
                                "device_instance": instance,
                                "ips": ips,
                            },
                        )
                        if a:
                            new_anomalies.append(a)

            # --- Foreign device registration failure ---
            if packet.bvlc and packet.bvlc.function == BVLC_RESULT:
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
        cooldown_subkey: str | None = None,
    ) -> Anomaly | None:
        """Create an anomaly if cooldown period has elapsed for this type+source.

        Args:
            cooldown_subkey: Optional extra discriminator for the cooldown key.
                Allows independent cooldown tracking for sub-categories of the
                same anomaly type (e.g., broadcast storm sub-types).
        """
        key = (anomaly_type.value, source_ip, cooldown_subkey)
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
            # Reset broadcast sub-type rate windows (including in check descriptors)
            for check in self._broadcast_checks.values():
                check.rate_window = _RateWindow(window_seconds=self._window_seconds)
            # Keep named attributes in sync for direct access
            self._discovery_rate = self._broadcast_checks["discovery"].rate_window
            self._timesync_rate = self._broadcast_checks["timesync"].rate_window
            self._unconfirmed_flood_rate = self._broadcast_checks["unconfirmed"].rate_window
            self._router_discovery_rate = self._broadcast_checks["router"].rate_window
            self._broadcast_rate = _RateWindow(window_seconds=self._window_seconds)
            # Reset PDU type rate windows
            for check in self._pdu_rate_checks:
                check.rate_window = _RateWindow(window_seconds=self._window_seconds)
            self._error_rate = self._pdu_rate_checks[0].rate_window
            self._reject_rate = self._pdu_rate_checks[1].rate_window
            self._abort_rate = self._pdu_rate_checks[2].rate_window
            self._anomalies.clear()
            self._last_alert.clear()
            self._instance_ips.clear()
