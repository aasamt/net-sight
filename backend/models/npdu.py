"""NPDU (Network Protocol Data Unit) layer model."""

from pydantic import BaseModel


# Network priority levels
NETWORK_PRIORITIES: dict[int, str] = {
    0: "Normal",
    1: "Urgent",
    2: "Critical-Equipment",
    3: "Life-Safety",
}

# Network layer message types
NETWORK_MESSAGE_TYPES: dict[int, str] = {
    0x00: "Who-Is-Router-To-Network",
    0x01: "I-Am-Router-To-Network",
    0x02: "I-Could-Be-Router-To-Network",
    0x03: "Reject-Message-To-Network",
    0x04: "Router-Busy-To-Network",
    0x05: "Router-Available-To-Network",
    0x06: "Initialize-Routing-Table",
    0x07: "Initialize-Routing-Table-Ack",
    0x08: "Establish-Connection-To-Network",
    0x09: "Disconnect-Connection-To-Network",
    0x0A: "Challenge-Request",
    0x0B: "Security-Payload",
    0x0C: "Security-Response",
    0x0D: "Request-Key-Update",
    0x0E: "Update-Key-Set",
    0x0F: "Update-Distribution-Key",
    0x10: "Request-Master-Key",
    0x11: "Set-Master-Key",
    0x12: "What-Is-Network-Number",
    0x13: "Network-Number-Is",
}

# Network reject reasons (for Reject-Message-To-Network, type 0x03)
NETWORK_REJECT_REASONS: dict[int, str] = {
    0: "Unknown-Error",
    1: "No-Route",
    2: "Router-Busy",
    3: "Unknown-Message-Type",
    4: "Message-Too-Long",
    5: "BACnet-Security-Error",
    6: "Bad-Address",
}


class NPDUMessage(BaseModel):
    """Parsed NPDU layer data."""

    version: int  # Always 0x01
    is_network_message: bool  # Control bit 7: True = network msg, False = APDU follows
    expecting_reply: bool  # Control bit 2
    priority: int  # Control bits 0-1 (0=Normal, 3=Life-Safety)
    priority_name: str

    # Destination (present if control bit 5 set)
    destination_network: int | None = None  # DNET (0xFFFF = broadcast all)
    destination_address: str | None = None  # DADR as hex string (empty = broadcast)

    # Source (present if control bit 3 set)
    source_network: int | None = None  # SNET
    source_address: str | None = None  # SADR as hex string

    hop_count: int | None = None  # Present if DNET present (default 255)

    # Network layer message fields (only if is_network_message is True)
    network_message_type: int | None = None
    network_message_name: str | None = None
    vendor_id: int | None = None  # Present if message type >= 0x80

    # For Reject-Message-To-Network
    reject_reason: int | None = None
    reject_reason_name: str | None = None
