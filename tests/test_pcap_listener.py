from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from fortipot.collector.pcap_listener import PacketCaptureListener
from fortipot.models import EventKind


def test_listener_blocks_and_yields_parsed_packets(monkeypatch) -> None:
    sniff_calls: list[dict] = []
    packet = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / IP(
        src="10.0.0.25", dst="10.0.0.10"
    ) / TCP(dport=22, flags="S")

    def fake_sniff(**kwargs):
        sniff_calls.append(kwargs)
        if len(sniff_calls) == 1:
            return [packet]
        raise KeyboardInterrupt

    monkeypatch.setattr("fortipot.collector.pcap_listener.sniff", fake_sniff)

    listener = PacketCaptureListener(interface="br0", promiscuous=True)

    events = list(listener.listen())

    assert len(events) == 1
    assert events[0].protocol == EventKind.TCP
    assert sniff_calls[0]["iface"] == "br0"
    assert sniff_calls[0]["filter"] is None
    assert sniff_calls[0]["promisc"] is True
