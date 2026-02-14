"""APDU (Application Protocol Data Unit) layer model."""

from pydantic import BaseModel


# PDU types (upper nibble of first APDU byte)
PDU_TYPES: dict[int, str] = {
    0: "Confirmed-Request",
    1: "Unconfirmed-Request",
    2: "Simple-ACK",
    3: "Complex-ACK",
    4: "Segment-ACK",
    5: "Error",
    6: "Reject",
    7: "Abort",
}

# Confirmed services (service choice codes)
CONFIRMED_SERVICES: dict[int, str] = {
    0: "AcknowledgeAlarm",
    1: "ConfirmedCOVNotification",
    2: "ConfirmedEventNotification",
    3: "GetAlarmSummary",
    4: "GetEnrollmentSummary",
    5: "SubscribeCOV",
    6: "AtomicReadFile",
    7: "AtomicWriteFile",
    8: "AddListElement",
    9: "RemoveListElement",
    10: "CreateObject",
    11: "DeleteObject",
    12: "ReadProperty",
    13: "ReadPropertyConditional",
    14: "ReadPropertyMultiple",
    15: "WriteProperty",
    16: "WritePropertyMultiple",
    17: "DeviceCommunicationControl",
    18: "ConfirmedPrivateTransfer",
    19: "ConfirmedTextMessage",
    20: "ReinitializeDevice",
    21: "VT-Open",
    22: "VT-Close",
    23: "VT-Data",
    24: "Authenticate",
    25: "RequestKey",
    26: "ReadRange",
    27: "LifeSafetyOperation",
    28: "SubscribeCOVProperty",
    29: "GetEventInformation",
    30: "SubscribeCOVPropertyMultiple",
    31: "ConfirmedCOVNotificationMultiple",
    32: "ConfirmedAuditNotification",
    33: "AuditLogQuery",
    34: "AuthRequest",
}

# Unconfirmed services (service choice codes)
UNCONFIRMED_SERVICES: dict[int, str] = {
    0: "I-Am",
    1: "I-Have",
    2: "UnconfirmedCOVNotification",
    3: "UnconfirmedEventNotification",
    4: "UnconfirmedPrivateTransfer",
    5: "UnconfirmedTextMessage",
    6: "TimeSynchronization",
    7: "Who-Has",
    8: "Who-Is",
    9: "UTC-TimeSynchronization",
    10: "WriteGroup",
    11: "UnconfirmedCOVNotificationMultiple",
    12: "UnconfirmedAuditNotification",
    13: "Who-Am-I",
    14: "You-Are",
}

# Error classes
ERROR_CLASSES: dict[int, str] = {
    0: "Device",
    1: "Object",
    2: "Property",
    3: "Resources",
    4: "Security",
    5: "Services",
    6: "VT",
    7: "Communication",
}

# Reject reasons
REJECT_REASONS: dict[int, str] = {
    0: "Other",
    1: "Buffer-Overflow",
    2: "Inconsistent-Parameters",
    3: "Invalid-Parameter-Data-Type",
    4: "Invalid-Tag",
    5: "Missing-Required-Parameter",
    6: "Parameter-Out-Of-Range",
    7: "Too-Many-Arguments",
    8: "Undefined-Enumeration",
    9: "Unrecognized-Service",
    10: "Invalid-Data-Encoding",
}

# Abort reasons
ABORT_REASONS: dict[int, str] = {
    0: "Other",
    1: "Buffer-Overflow",
    2: "Invalid-APDU-In-This-State",
    3: "Preempted-By-Higher-Priority-Task",
    4: "Segmentation-Not-Supported",
    5: "Security-Error",
    6: "Insufficient-Security",
    7: "Window-Size-Out-Of-Range",
    8: "Application-Exceeded-Reply-Time",
    9: "Out-Of-Resources",
    10: "TSM-Timeout",
    11: "APDU-Too-Long",
}

# BACnet object types (commonly seen in traffic)
OBJECT_TYPES: dict[int, str] = {
    0: "Analog-Input",
    1: "Analog-Output",
    2: "Analog-Value",
    3: "Binary-Input",
    4: "Binary-Output",
    5: "Binary-Value",
    6: "Calendar",
    7: "Command",
    8: "Device",
    9: "Event-Enrollment",
    10: "File",
    11: "Group",
    12: "Loop",
    13: "Multi-state-Input",
    14: "Multi-state-Output",
    15: "Notification-Class",
    16: "Program",
    17: "Schedule",
    18: "Averaging",
    19: "Multi-state-Value",
    20: "Trend-Log",
    56: "Network-Port",
}

# BACnet property identifiers (commonly seen in traffic)
PROPERTY_IDENTIFIERS: dict[int, str] = {
    8: "All",
    28: "Description",
    36: "Event-State",
    46: "Max-APDU-Length-Accepted",
    55: "Object-Identifier",
    62: "Object-List",
    70: "Object-Name",
    75: "Object-Type",
    76: "Optional",
    77: "Out-Of-Service",
    79: "Present-Value",
    81: "Priority-Array",
    85: "Present-Value",  # alias
    87: "Priority-Array",  # alias
    95: "Reliability",
    96: "Relinquish-Default",
    97: "Required",
    103: "Segmentation-Supported",
    104: "Setpoint-Reference",
    107: "Status-Flags",
    112: "System-Status",
    120: "Vendor-Identifier",
    121: "Vendor-Name",
    139: "Protocol-Object-Types-Supported",
    140: "Protocol-Services-Supported",
    152: "Max-Segments-Accepted",
    155: "Protocol-Version",
    168: "Model-Name",
    169: "Firmware-Revision",
    170: "Application-Software-Version",
    371: "Property-List",
    512: "Database-Revision",
}

# BACnet segmentation support values (for I-Am)
SEGMENTATION_VALUES: dict[int, str] = {
    0: "Segmented-Both",
    1: "Segmented-Transmit",
    2: "Segmented-Receive",
    3: "No-Segmentation",
}


class ObjectIdentifier(BaseModel):
    """BACnet object identifier (32-bit: 10-bit type + 22-bit instance)."""

    object_type: int
    object_type_name: str
    instance: int


class IAmFields(BaseModel):
    """Decoded I-Am service data fields."""

    device_instance: int  # Device object instance from object ID
    max_apdu_length: int  # Max APDU length accepted
    segmentation_supported: int  # 0-3 segmentation code
    segmentation_name: str  # Human-readable segmentation
    vendor_id: int  # Vendor identifier


class WhoIsRange(BaseModel):
    """Decoded Who-Is service data fields (optional range)."""

    low_limit: int  # Low device instance limit
    high_limit: int  # High device instance limit


class APDUMessage(BaseModel):
    """Parsed APDU layer data."""

    pdu_type: int  # 0-7
    pdu_type_name: str  # Human-readable PDU type
    service_choice: int | None = None  # Service code
    service_name: str | None = None  # Human-readable service name
    is_confirmed: bool = False  # True for confirmed request/response types

    # Request fields
    invoke_id: int | None = None  # Transaction ID

    # Segmentation
    segmented: bool = False
    more_follows: bool = False
    sequence_number: int | None = None
    window_size: int | None = None
    max_segments: int | None = None
    max_apdu_length: int | None = None

    # Error PDU (type 5)
    error_class: int | None = None
    error_class_name: str | None = None
    error_code: int | None = None

    # Reject PDU (type 6)
    reject_reason: int | None = None
    reject_reason_name: str | None = None

    # Abort PDU (type 7)
    abort_reason: int | None = None
    abort_reason_name: str | None = None

    # Object identifier (extracted from service data when available)
    object_identifier: ObjectIdentifier | None = None

    # Property identifier (ReadProperty, WriteProperty, etc.)
    property_identifier: int | None = None
    property_name: str | None = None
    property_array_index: int | None = None  # Optional array index

    # Service-specific decoded fields
    iam_fields: IAmFields | None = None  # I-Am response data
    who_is_range: WhoIsRange | None = None  # Who-Is request range

    # Raw service data payload (hex string, after APDU header)
    service_data_hex: str | None = None
