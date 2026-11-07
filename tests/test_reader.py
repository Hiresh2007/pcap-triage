from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.utils import wrpcapng

from pcap_triage.flows import summarize
from pcap_triage.reader import ACK, SYN, read_packets

from .conftest import MAC_A, T0, eth, stamp


def ip4(dst, layer4, ts):
    return stamp(eth() / IP(src="192.0.2.1", dst=dst) / layer4, ts)


def mixed_packets():
    v6 = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=2222, dport=443, flags="SA")
    arp = ARP(hwsrc=MAC_A, psrc="192.0.2.1", pdst="192.0.2.2")
    return [
        ip4("192.0.2.2", TCP(sport=1111, dport=80, flags="S"), T0),
        ip4("192.0.2.53", UDP(sport=5353, dport=53), T0 + 1),
        ip4("192.0.2.2", ICMP(), T0 + 2),
        stamp(eth() / v6, T0 + 3),
        stamp(eth("ff:ff:ff:ff:ff:ff") / arp, T0 + 4),
    ]


def test_reader_converts_ip_and_counts_non_ip(write_pcap):
    records, stats = read_packets(write_pcap(mixed_packets()))

    assert stats.total_frames == 5
    assert stats.ip_packets == 4
    assert stats.non_ip_frames == 1
    assert [r.proto for r in records] == ["TCP", "UDP", "ICMP", "TCP"]

    syn, udp, icmp, v6 = records
    assert syn.is_syn_only and not syn.is_syn_ack
    assert syn.tcp_flags == SYN
    assert (udp.sport, udp.dport) == (5353, 53)
    assert icmp.sport is None and icmp.dport is None
    assert v6.src == "2001:db8::1" and v6.is_syn_ack
    assert v6.tcp_flags == SYN | ACK
    assert syn.ts == T0


def test_reader_handles_pcapng(tmp_path):
    path = tmp_path / "capture.pcapng"
    wrpcapng(str(path), mixed_packets())
    records, stats = read_packets(path)
    assert stats.ip_packets == 4
    assert records[0].dport == 80


def test_summary_builds_directional_flows(write_pcap):
    records, _ = read_packets(write_pcap(mixed_packets()))
    summary = summarize(records)

    assert summary.packets == 4
    assert summary.protocols == {"TCP": 2, "UDP": 1, "ICMP": 1}
    assert len(summary.flows) == 4
    assert summary.first_seen == T0 and summary.last_seen == T0 + 3
    assert summary.duration == 3
    assert summary.top_talkers(1)[0][0] == "192.0.2.1"
    assert sum(f.bytes for f in summary.flows.values()) == summary.bytes


def test_summary_aggregates_repeated_packets_into_one_flow(write_pcap):
    pkts = [
        ip4("192.0.2.2", TCP(sport=1111, dport=80, flags=f), T0 + i)
        for i, f in enumerate(["S", "A", "PA", "FA"])
    ]
    records, _ = read_packets(write_pcap(pkts))
    (flow,) = summarize(records).flows.values()
    assert flow.packets == 4
    assert flow.duration == 3
    assert flow.tcp_flags_seen & SYN and flow.tcp_flags_seen & ACK
