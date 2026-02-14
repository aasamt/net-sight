"""Unified parsed packet model — combines all BACnet layers."""

from pydantic import BaseModel

from backend.models.bvlc import BVLCMessage
from backend.models.npdu import NPDUMessage
from backend.models.apdu import APDUMessage


class ParsedPacket(BaseModel):
    """Complete parsed BACnet/IP packet with all protocol layers."""

    # Packet metadata
    id: int  # Sequence number within capture session
    timestamp: float  # Unix timestamp (from Scapy pkt.time)
    length: int  # Total packet length in bytes

    # IP layer
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int

    # Effective source — resolves Forwarded-NPDU originating address
    effective_source_ip: str  # The actual originating device IP
    effective_source_port: int

    # Raw payload
    raw_hex: str  # UDP payload as hex string for display/inspection

    # Decoded BACnet layers (None if that layer failed to parse)
    bvlc: BVLCMessage | None = None
    npdu: NPDUMessage | None = None
    apdu: APDUMessage | None = None

    # Error tracking — malformed packets are logged, not dropped
    parse_error: str | None = None

    @property
    def summary(self) -> str:
        """One-line summary for terminal output."""
        service = ""
        if self.apdu and self.apdu.service_name:
            service = self.apdu.service_name
        elif self.npdu and self.npdu.network_message_name:
            service = self.npdu.network_message_name
        elif self.bvlc:
            service = self.bvlc.function_name

        bvlc_fn = self.bvlc.function_name if self.bvlc else "Unknown"

        return (
            f"#{self.id:<6} "
            f"{self.effective_source_ip:<15} → {self.destination_ip:<15}  "
            f"{bvlc_fn:<20} {service:<30} "
            f"{self.length}B"
        )
