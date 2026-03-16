"""Passive pcap listener."""

from __future__ import annotations

from collections.abc import Iterable

from scapy.all import sniff
from scapy.error import Scapy_Exception

from fortipot.collector.packet_parser import parse_packet
from fortipot.logging_utils import get_logger
from fortipot.models import PacketEvent

logger = get_logger(__name__)


class PacketCaptureListener:
    """Passive packet listener abstraction."""

    def __init__(self, interface: str, bpf_filter: str = "", promiscuous: bool = True) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.promiscuous = promiscuous

    def listen(self) -> Iterable[PacketEvent]:
        """Yield normalized packet events from a live interface."""

        logger.info(
            "pcap_listener_started",
            interface=self.interface,
            bpf_filter=self.bpf_filter,
            promiscuous=self.promiscuous,
        )
        try:
            while True:
                packets = sniff(
                    iface=self.interface,
                    filter=self.bpf_filter or None,
                    count=1,
                    store=True,
                    promisc=self.promiscuous,
                    timeout=1,
                )
                for packet in packets:
                    event = parse_packet(packet)
                    if event is not None:
                        yield event
        except KeyboardInterrupt:
            logger.info("pcap_listener_stopped", interface=self.interface, reason="keyboard_interrupt")
            return
        except (OSError, PermissionError, Scapy_Exception) as exc:
            logger.error(
                "pcap_listener_failed",
                interface=self.interface,
                error=str(exc),
            )
            raise
