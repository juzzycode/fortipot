from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import ARP, Ether

from fortipot.collector.packet_parser import parse_packet
from fortipot.models import EventKind


def test_parse_packet_normalizes_tcp_metadata() -> None:
    packet = Ether(src="AA:BB:CC:DD:EE:FF", dst="11:22:33:44:55:66") / IP(
        src="10.0.0.25", dst="10.0.0.10"
    ) / TCP(dport=445, flags="S")
    packet.sniffed_on = "br0"

    event = parse_packet(packet)

    assert event is not None
    assert event.protocol == EventKind.TCP
    assert event.src_ip == "10.0.0.25"
    assert event.dst_ip == "10.0.0.10"
    assert event.dst_port == 445
    assert event.tcp_flags == "S"
    assert event.src_mac == "aa:bb:cc:dd:ee:ff"
    assert event.metadata["interface"] == "br0"


def test_parse_packet_normalizes_arp_event() -> None:
    packet = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / ARP(
        psrc="10.0.0.25",
        pdst="10.0.0.1",
        hwsrc="aa:bb:cc:dd:ee:ff",
    )

    event = parse_packet(packet)

    assert event is not None
    assert event.protocol == EventKind.ARP
    assert event.src_ip == "10.0.0.25"
    assert event.arp_target_ip == "10.0.0.1"


def test_parse_packet_ignores_unsupported_frames() -> None:
    packet = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / ICMP()

    assert parse_packet(packet) is None
