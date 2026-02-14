"""BACnet/IP live capture transport using Scapy AsyncSniffer."""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import sys
from typing import Any

from scapy.all import AsyncSniffer, IP, UDP, conf

from backend.transport.base import RawPacket, TransportCapture

logger = logging.getLogger(__name__)

# BACnet/IP uses UDP port 47808 (0xBAC0)
BACNET_PORT = 47808
BPF_FILTER = f"udp port {BACNET_PORT}"


class BACnetIPCapture(TransportCapture):
    """Live BACnet/IP packet capture using Scapy AsyncSniffer.

    Uses a BPF kernel filter to capture only BACnet/IP traffic (UDP 47808).
    Packets are delivered to the registered callback with minimal processing
    in the capture thread — raw bytes are extracted and queued.

    Args:
        interface: Network interface name (e.g., 'en0', 'eth0').
                   If None, Scapy will use the default interface.
    """

    def __init__(self, interface: str | None = None) -> None:
        super().__init__()
        self._interface = interface
        self._sniffer: AsyncSniffer | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def interface(self) -> str | None:
        """The network interface being captured on."""
        return self._interface

    @interface.setter
    def interface(self, value: str | None) -> None:
        """Set the network interface. Cannot change while running."""
        if self._running:
            raise RuntimeError("Cannot change interface while capture is running")
        self._interface = value

    async def start(self) -> None:
        """Start live BACnet/IP capture on the configured interface.

        Raises:
            RuntimeError: If no callback registered or already running.
            PermissionError: If insufficient privileges for packet capture.
        """
        if self._callback is None:
            raise RuntimeError("No packet callback registered. Call on_packet() first.")
        if self._running:
            raise RuntimeError("Capture is already running")

        self._check_privileges()
        self._loop = asyncio.get_running_loop()

        sniffer_kwargs: dict[str, Any] = {
            "filter": BPF_FILTER,
            "prn": self._on_packet,
            "store": False,  # Critical: don't accumulate packets in memory
        }

        if self._interface:
            sniffer_kwargs["iface"] = self._interface

        self._sniffer = AsyncSniffer(**sniffer_kwargs)
        self._sniffer.start()
        self._running = True

        logger.info(
            "BACnet/IP capture started on %s (filter: %s)",
            self._interface or "default interface",
            BPF_FILTER,
        )

    async def stop(self) -> None:
        """Stop the active capture. Safe to call if not running."""
        if not self._running or self._sniffer is None:
            return

        self._sniffer.stop()
        self._sniffer = None
        self._running = False
        self._loop = None

        logger.info("BACnet/IP capture stopped")

    def _on_packet(self, pkt: Any) -> None:
        """Scapy prn callback — runs in the sniffer thread.

        Extracts minimal data and invokes the registered callback.
        Keeps work minimal to avoid dropping packets at high rates.
        """
        if self._callback is None or not self._running:
            return

        try:
            if IP not in pkt or UDP not in pkt:
                return

            raw_bytes = bytes(pkt[UDP].payload)
            if not raw_bytes:
                return

            raw_packet = RawPacket(
                timestamp=float(pkt.time),
                raw_bytes=raw_bytes,
                source_ip=pkt[IP].src,
                source_port=pkt[UDP].sport,
                destination_ip=pkt[IP].dst,
                destination_port=pkt[UDP].dport,
                length=len(pkt),
            )

            self._callback(raw_packet)

        except Exception:
            # Never crash the capture thread — log and continue
            logger.exception("Error processing captured packet")

    @staticmethod
    def list_interfaces() -> list[dict[str, str]]:
        """List available network interfaces.

        Returns:
            List of dicts with 'name', 'description', and 'ip' keys.
        """
        interfaces = []
        try:
            for iface_name, iface_data in conf.ifaces.items():
                ip = getattr(iface_data, "ip", "") or ""
                description = getattr(iface_data, "description", "") or str(iface_name)
                interfaces.append({
                    "name": str(iface_name),
                    "description": description,
                    "ip": ip,
                })
        except Exception:
            logger.exception("Error listing network interfaces")

        return interfaces

    @staticmethod
    def _check_privileges() -> None:
        """Check if we have sufficient privileges for packet capture.

        Raises:
            PermissionError: If running without required privileges.
        """
        system = platform.system()

        if system == "Darwin":
            # macOS: need root or access to /dev/bpf*
            if os.geteuid() != 0:
                # Check if any BPF device is readable
                bpf_accessible = any(
                    os.access(f"/dev/bpf{i}", os.R_OK) for i in range(10)
                )
                if not bpf_accessible:
                    raise PermissionError(
                        "Live capture requires root privileges on macOS. "
                        "Run with: sudo uv run python -m backend.main -i <interface>"
                    )

        elif system == "Windows":
            # Windows: check for Npcap
            npcap_path = os.path.join(
                os.environ.get("WINDIR", r"C:\Windows"),
                "System32", "Npcap"
            )
            if not os.path.isdir(npcap_path):
                raise PermissionError(
                    "Npcap is required for packet capture on Windows. "
                    "Install from https://npcap.com/"
                )

        elif system == "Linux":
            if os.geteuid() != 0:
                raise PermissionError(
                    "Live capture requires root or CAP_NET_RAW capability. "
                    "Run with: sudo uv run python -m backend.main -i <interface>"
                )
