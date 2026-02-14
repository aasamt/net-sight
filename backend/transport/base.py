"""Abstract base class for all packet capture transports."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable


@dataclass
class RawPacket:
    """Raw packet data passed from transport to parser pipeline.

    This is the minimal data extracted in the capture callback.
    Keep it lightweight — no parsing happens at this stage.
    """

    timestamp: float  # Unix timestamp (from Scapy pkt.time)
    raw_bytes: bytes  # UDP payload (BVLC + NPDU + APDU)
    source_ip: str  # IP source address
    source_port: int  # UDP source port
    destination_ip: str  # IP destination address
    destination_port: int  # UDP destination port
    length: int  # Total packet length (including IP/UDP headers)


# Type alias for packet callback: receives a RawPacket
PacketCallback = Callable[[RawPacket], None]


class TransportCapture(ABC):
    """Abstract base class for BACnet packet capture transports.

    All capture sources (BACnet/IP live, pcap replay, future MS/TP)
    implement this interface. The parser pipeline and analysis engine
    consume packets through the registered callback, regardless of source.
    """

    def __init__(self) -> None:
        self._callback: PacketCallback | None = None
        self._running: bool = False

    @property
    def is_running(self) -> bool:
        """Whether capture is currently active."""
        return self._running

    def on_packet(self, callback: PacketCallback) -> None:
        """Register a callback to receive captured packets.

        The callback is invoked for each captured packet with a RawPacket.
        Only one callback is supported — calling again replaces the previous one.

        Args:
            callback: Function that receives a RawPacket.
        """
        self._callback = callback

    @abstractmethod
    async def start(self) -> None:
        """Start capturing packets.

        Raises:
            RuntimeError: If no callback is registered via on_packet().
            PermissionError: If insufficient privileges for live capture.
        """
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Stop capturing packets. Safe to call if not running."""
        ...

    @staticmethod
    @abstractmethod
    def list_interfaces() -> list[dict[str, str]]:
        """List available network interfaces for capture.

        Returns:
            List of dicts with keys: 'name', 'description', 'ip'.
        """
        ...
