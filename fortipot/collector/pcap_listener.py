"""Passive pcap listener scaffold."""

from __future__ import annotations

from collections.abc import Iterable

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
        """Yield normalized packet events.

        This MVP intentionally leaves live capture as a scaffold so tests and
        simulations can exercise the detector without requiring privileged capture.
        """

        logger.info(
            "pcap_listener_idle",
            interface=self.interface,
            bpf_filter=self.bpf_filter,
            promiscuous=self.promiscuous,
        )
        return []
