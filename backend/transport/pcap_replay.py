"""Pcap file replay transport — imports and replays captured BACnet/IP traffic."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from scapy.all import IP, UDP, PcapReader, rdpcap

from backend.transport.base import RawPacket, TransportCapture

logger = logging.getLogger(__name__)


class PcapReplayCapture(TransportCapture):
    """Replay BACnet/IP packets from a pcap file.

    Reads a pcap file (from Wireshark, tcpdump, or a previous NetSight session)
    and replays packets through the same callback pipeline as live capture.

    Args:
        file_path: Path to the pcap file to replay.
        replay_speed: Speed multiplier for replay timing.
                      1.0 = real-time, 0.0 = as fast as possible (default),
                      2.0 = double speed, etc.
    """

    def __init__(self, file_path: str | Path, replay_speed: float = 0.0) -> None:
        super().__init__()
        self._file_path = Path(file_path)
        self._replay_speed = replay_speed
        self._task: asyncio.Task | None = None

    @property
    def file_path(self) -> Path:
        """The pcap file being replayed."""
        return self._file_path

    @file_path.setter
    def file_path(self, value: str | Path) -> None:
        """Set the pcap file. Cannot change while running."""
        if self._running:
            raise RuntimeError("Cannot change file while replay is running")
        self._file_path = Path(value)

    async def start(self) -> None:
        """Start replaying packets from the pcap file.

        Raises:
            RuntimeError: If no callback registered or already running.
            FileNotFoundError: If the pcap file doesn't exist.
            ValueError: If the file is not a valid pcap file.
        """
        if self._callback is None:
            raise RuntimeError("No packet callback registered. Call on_packet() first.")
        if self._running:
            raise RuntimeError("Replay is already running")
        if not self._file_path.exists():
            raise FileNotFoundError(f"Pcap file not found: {self._file_path}")

        self._running = True
        self._task = asyncio.create_task(self._replay_packets())

        logger.info(
            "Pcap replay started: %s (speed: %s)",
            self._file_path,
            "max" if self._replay_speed == 0.0 else f"{self._replay_speed}x",
        )

    async def stop(self) -> None:
        """Stop the replay. Safe to call if not running."""
        if not self._running:
            return

        self._running = False

        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        self._task = None
        logger.info("Pcap replay stopped")

    async def _replay_packets(self) -> None:
        """Read and replay all packets from the pcap file."""
        packet_count = 0
        first_timestamp: float | None = None
        replay_start: float | None = None

        try:
            with PcapReader(str(self._file_path)) as reader:
                for pkt in reader:
                    if not self._running:
                        break

                    # Only process BACnet/IP packets (UDP port 47808)
                    if IP not in pkt or UDP not in pkt:
                        continue
                    if pkt[UDP].sport != 47808 and pkt[UDP].dport != 47808:
                        continue

                    raw_bytes = bytes(pkt[UDP].payload)
                    if not raw_bytes:
                        continue

                    # Replay timing
                    pkt_time = float(pkt.time)
                    if self._replay_speed > 0.0:
                        if first_timestamp is None:
                            first_timestamp = pkt_time
                            replay_start = asyncio.get_event_loop().time()
                        else:
                            elapsed_in_pcap = pkt_time - first_timestamp
                            target_delay = elapsed_in_pcap / self._replay_speed
                            elapsed_replay = asyncio.get_event_loop().time() - replay_start
                            wait_time = target_delay - elapsed_replay
                            if wait_time > 0:
                                await asyncio.sleep(wait_time)
                    else:
                        # Yield control periodically to avoid blocking the event loop
                        if packet_count % 100 == 0:
                            await asyncio.sleep(0)

                    raw_packet = RawPacket(
                        timestamp=pkt_time,
                        raw_bytes=raw_bytes,
                        source_ip=pkt[IP].src,
                        source_port=pkt[UDP].sport,
                        destination_ip=pkt[IP].dst,
                        destination_port=pkt[UDP].dport,
                        length=len(pkt),
                    )

                    try:
                        self._callback(raw_packet)
                    except Exception:
                        logger.exception("Error in packet callback during replay")

                    packet_count += 1

        except asyncio.CancelledError:
            logger.debug("Pcap replay cancelled after %d packets", packet_count)
            raise
        except Exception:
            logger.exception("Error reading pcap file: %s", self._file_path)
        finally:
            self._running = False
            logger.info(
                "Pcap replay finished: %d BACnet packets from %s",
                packet_count,
                self._file_path,
            )

    @staticmethod
    def list_interfaces() -> list[dict[str, str]]:
        """Not applicable for pcap replay — returns empty list."""
        return []
