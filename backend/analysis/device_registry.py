"""Device registry — accumulates BACnet devices discovered from I-Am responses.

Tracks each device by its object instance number and correlates IP addresses
to devices so that all packet types (not just I-Am) get attributed correctly.

Thread-safe: all public methods can be called from async consumer or capture thread.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from threading import Lock

from backend.models.packet import ParsedPacket

logger = logging.getLogger(__name__)


@dataclass
class DeviceEntry:
    """Tracked state for a single BACnet device."""

    instance: int  # Device object instance number (from I-Am)
    ip: str  # IP address where the device was seen
    port: int = 47808

    # Vendor info (from I-Am service data if available)
    vendor_id: int | None = None

    # Timestamps
    first_seen: float = 0.0
    last_seen: float = 0.0

    # Traffic counters
    packet_count: int = 0
    byte_count: int = 0

    # Object type seen in I-Am
    object_type: int = 8  # Device (default)
    object_type_name: str = "Device"

    def to_dict(self) -> dict:
        """Serialize for JSON/WebSocket output."""
        return {
            "instance": self.instance,
            "ip": self.ip,
            "port": self.port,
            "vendor_id": self.vendor_id,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
        }


class DeviceRegistry:
    """Accumulates BACnet devices from parsed packets.

    Devices are indexed by instance number (from I-Am). IP-to-device mapping
    allows attributing non-I-Am packets to known devices.

    Usage:
        registry = DeviceRegistry()
        registry.process_packet(parsed_packet)  # Call for every packet
        devices = registry.get_all_devices()     # Snapshot of all known devices
    """

    def __init__(self) -> None:
        self._devices: dict[int, DeviceEntry] = {}  # instance → DeviceEntry
        self._ip_to_instance: dict[str, int] = {}  # IP → device instance
        self._lock = Lock()

    def process_packet(self, packet: ParsedPacket) -> None:
        """Process a parsed packet to update device registry.

        - I-Am packets register/update a device entry
        - All packets increment counters for the source device (if known)
        """
        with self._lock:
            self._process_iam(packet)
            self._attribute_traffic(packet)

    def _process_iam(self, packet: ParsedPacket) -> None:
        """Register or update a device from an I-Am response."""
        if not packet.apdu:
            return
        if packet.apdu.pdu_type != 1 or packet.apdu.service_choice != 0:
            return  # Not an I-Am (unconfirmed service 0)

        obj_id = packet.apdu.object_identifier
        if not obj_id:
            return

        instance = obj_id.instance
        ip = packet.effective_source_ip
        port = packet.effective_source_port

        if instance in self._devices:
            # Update existing device
            dev = self._devices[instance]
            dev.last_seen = packet.timestamp
            dev.ip = ip
            dev.port = port
        else:
            # New device discovered
            dev = DeviceEntry(
                instance=instance,
                ip=ip,
                port=port,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
                object_type=obj_id.object_type,
                object_type_name=obj_id.object_type_name,
            )
            self._devices[instance] = dev
            logger.info(
                "New device discovered: Device:%d at %s:%d",
                instance, ip, port,
            )

        # Map IP to device instance
        self._ip_to_instance[ip] = instance

    def _attribute_traffic(self, packet: ParsedPacket) -> None:
        """Attribute packet traffic to a known device by source IP."""
        ip = packet.effective_source_ip
        instance = self._ip_to_instance.get(ip)
        if instance is None:
            return

        dev = self._devices.get(instance)
        if dev is None:
            return

        dev.packet_count += 1
        dev.byte_count += packet.length
        dev.last_seen = max(dev.last_seen, packet.timestamp)

    def get_device(self, instance: int) -> DeviceEntry | None:
        """Get a single device by instance number."""
        with self._lock:
            dev = self._devices.get(instance)
            return dev

    def get_device_by_ip(self, ip: str) -> DeviceEntry | None:
        """Get a device by its IP address."""
        with self._lock:
            instance = self._ip_to_instance.get(ip)
            if instance is None:
                return None
            return self._devices.get(instance)

    def get_all_devices(self) -> list[DeviceEntry]:
        """Get a snapshot of all known devices."""
        with self._lock:
            return list(self._devices.values())

    def get_device_count(self) -> int:
        """Get the number of known devices."""
        with self._lock:
            return len(self._devices)

    def to_dict_list(self) -> list[dict]:
        """Serialize all devices for JSON output."""
        with self._lock:
            return [dev.to_dict() for dev in self._devices.values()]

    def reset(self) -> None:
        """Clear all device state. Used when starting a new capture session."""
        with self._lock:
            self._devices.clear()
            self._ip_to_instance.clear()
