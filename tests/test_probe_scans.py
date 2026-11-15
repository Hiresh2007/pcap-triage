import pytest
from scapy.layers.inet import ICMP, IP, UDP, IPerror, UDPerror

from pcap_triage.detectors import detect_port_scans
from pcap_triage.reader import read_packets

from .conftest import SCANNER, T0, TARGET, eth, stamp, tcp


def run(write_pcap, packets):
    records, _ = read_packets(write_pcap(packets))
    return [f for f in detect_port_scans(records) if f.detector != "portscan.vertical"]


def stealth_scan(flags, ports=range(1, 31), closed=range(1, 21)):
    pkts = []
    for i, port in enumerate(ports):
        ts = T0 + i * 0.01
        pkts.append(tcp(SCANNER, TARGET, 41000, port, flags, ts))
        if port in closed:
            pkts.append(tcp(TARGET, SCANNER, port, 41000, "RA", ts + 0.001))
    return pkts


def udp_probe(port, ts, sport=53415):
    return stamp(eth() / IP(src=SCANNER, dst=TARGET) / UDP(sport=sport, dport=port), ts)


def port_unreachable(port, ts, sport=53415):
    quoted = IPerror(src=SCANNER, dst=TARGET) / UDPerror(sport=sport, dport=port)
    return stamp(eth() / IP(src=TARGET, dst=SCANNER) / ICMP(type=3, code=3) / quoted, ts)


@pytest.mark.parametrize(
    ("flags", "kind"), [("", "null"), ("F", "fin"), ("FPU", "xmas")]
)  # fmt: skip
def test_detects_stealth_tcp_scans(write_pcap, flags, kind):
    (f,) = run(write_pcap, stealth_scan(flags))
    assert f.detector == f"portscan.{kind}"
    assert f.attack_technique == "T1046"
    assert (f.src, f.dst) == (SCANNER, TARGET)
    assert f.evidence["distinct_ports_in_window"] == 30
    assert f.evidence["closed_ports"] == 20
    assert f.evidence["open_or_filtered_ports"] == 10


def test_normal_fin_ack_teardown_is_not_a_fin_scan(write_pcap):
    # FIN+ACK closes real connections and must not count as a FIN probe
    assert run(write_pcap, stealth_scan("FA")) == []


def test_few_stealth_probes_below_threshold(write_pcap):
    assert run(write_pcap, stealth_scan("FPU", ports=range(1, 6))) == []


def test_detects_udp_scan_with_icmp_closed_ports(write_pcap):
    pkts = []
    for i, port in enumerate(range(100, 140)):
        ts = T0 + i * 0.05
        pkts.append(udp_probe(port, ts))
        if port % 2 == 0:
            pkts.append(port_unreachable(port, ts + 0.01))
    (f,) = run(write_pcap, pkts)
    assert f.detector == "portscan.udp"
    assert f.evidence["distinct_ports_in_window"] == 40
    assert f.evidence["closed_ports"] == 20
    assert f.evidence["open_or_filtered_ports"] == 20


def test_reader_extracts_icmp_quoted_port(write_pcap):
    (rec,), _ = read_packets(write_pcap([port_unreachable(161, T0)]))
    assert (rec.proto, rec.icmp_type, rec.icmp_code, rec.quoted_dport) == ("ICMP", 3, 3, 161)


def test_dns_replies_to_many_client_ports_not_a_udp_scan(write_pcap):
    # a resolver answering one client from port 53 to 40 different ephemeral ports
    pkts = [
        stamp(eth() / IP(src=TARGET, dst=SCANNER) / UDP(sport=53, dport=50000 + i), T0 + i * 0.1)
        for i in range(40)
    ]
    assert run(write_pcap, pkts) == []
