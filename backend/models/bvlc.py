"""BVLC (BACnet Virtual Link Control) layer model."""

from pydantic import BaseModel


# BVLC function code → human-readable name
BVLC_FUNCTIONS: dict[int, str] = {
    0x00: "BVLC-Result",
    0x01: "Write-BDT",
    0x02: "Read-BDT",
    0x03: "Read-BDT-Ack",
    0x04: "Forwarded-NPDU",
    0x05: "Register-Foreign-Device",
    0x06: "Read-FDT",
    0x07: "Read-FDT-Ack",
    0x08: "Delete-FDT-Entry",
    0x09: "Distribute-Broadcast-To-Network",
    0x0A: "Original-Unicast-NPDU",
    0x0B: "Original-Broadcast-NPDU",
    0x0C: "Secure-BVLL",
}

# BVLC result codes
BVLC_RESULT_CODES: dict[int, str] = {
    0x0000: "Successful-Completion",
    0x0010: "Write-BDT-NAK",
    0x0020: "Read-BDT-NAK",
    0x0030: "Register-Foreign-Device-NAK",
    0x0040: "Read-FDT-NAK",
    0x0050: "Delete-FDT-Entry-NAK",
    0x0060: "Distribute-Broadcast-To-Network-NAK",
}


class BVLCMessage(BaseModel):
    """Parsed BVLC layer data."""

    type: int  # Always 0x81 for BACnet/IPv4
    function: int  # BVLC function code (0x00–0x0C)
    function_name: str  # Human-readable function name
    length: int  # Total BVLC message length

    # Forwarded-NPDU (function 0x04): 6-byte originating address
    originating_ip: str | None = None  # e.g. "192.168.1.10"
    originating_port: int | None = None  # e.g. 47808

    # BVLC-Result (function 0x00)
    result_code: int | None = None
    result_name: str | None = None

    # Register-Foreign-Device (function 0x05)
    ttl: int | None = None  # Time-to-live in seconds
