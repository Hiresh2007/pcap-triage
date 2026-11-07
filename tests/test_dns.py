import hashlib
import json

import pytest
from scapy.layers.inet import IP, UDP

from pcap_triage.detectors import DnsConfig, Severity, detect_dns_anomalies
from pcap_triage.detectors.dns import shannon_entropy, split_name
from pcap_triage.reader import read_packets

from .conftest import CLIENT, RESOLVER, T0, dns_query, dns_reply, eth, stamp


def run(write_pcap, packets, **cfg):
    records, _ = read_packets(write_pcap(packets))
    return detect_dns_anomalies(records, DnsConfig(**cfg))


def hex_chunk(i: int, n: int = 32) -> str:
    """Deterministic hex label, like data encoded by a DNS tunnelling client."""
    return hashlib.sha256(str(i).encode()).hexdigest()[:n]


def tunnel_traffic(count=40, base="t.example.net"):
    return [dns_query(f"{hex_chunk(i)}.{base}", T0 + i * 0.2, qtype="TXT") for i in range(count)]


def browsing_traffic():
    names = ["www.example.com", "mail.example.com", "cdn.example.org", "api.example.org"]
    pkts = []
    for i in range(60):
        name = names[i % len(names)]
        pkts += [dns_query(name, T0 + i), dns_reply(name, T0 + i + 0.01)]
    return pkts


# --- helpers -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [("", 0.0), ("aaaa", 0.0), ("ab", 1.0), ("0123456789abcdef", 4.0)],
)
def test_shannon_entropy(text, expected):
    assert shannon_entropy(text) == pytest.approx(expected)


@pytest.mark.parametrize(
    ("qname", "expected"),
    [
        ("example.com", ("", "example.com")),
        ("www.example.com", ("www", "example.com")),
        ("a.b.example.com", ("a.b", "example.com")),
        ("x.bbc.co.uk", ("x", "bbc.co.uk")),
        ("bbc.co.uk", ("", "bbc.co.uk")),
        ("localhost", ("", "localhost")),
    ],
)
def test_split_name(qname, expected):
    assert split_name(qname) == expected


# --- reader ---------------------------------------------------------------------


def test_reader_extracts_dns_fields(write_pcap):
    pkts = [
        dns_query("WWW.Example.COM.", T0, qtype="TXT"),
        dns_reply("nx.example", T0 + 1, rcode=3),
    ]
    (q, r), _ = read_packets(write_pcap(pkts))
    assert (q.dns.qname, q.dns.qtype, q.dns.is_response) == ("www.example.com", 16, False)
    assert (r.dns.qname, r.dns.is_response, r.dns.rcode) == ("nx.example", True, 3)


def test_reader_tolerates_non_dns_payload_on_port_53(write_pcap):
    junk = stamp(eth() / IP(src=CLIENT, dst=RESOLVER) / UDP(sport=5000, dport=53) / b"\x00junk", T0)
    (rec,), stats = read_packets(write_pcap([junk]))
    assert rec.dns is None and stats.ip_packets == 1


def test_reader_escapes_control_bytes_in_names(write_pcap):
    # ESC [ 31 m would recolour the analyst's terminal if printed raw
    (rec,), _ = read_packets(write_pcap([dns_query(b"evil\x1b[31m.example.com", T0)]))
    assert rec.dns.qname == r"evil\x1b[31m.example.com"
    assert "\x1b" not in rec.dns.qname


# --- tunnelling --------------------------------------------------------------


def test_detects_dns_tunnel(write_pcap):
    (f,) = run(write_pcap, tunnel_traffic())
    assert f.detector == "dns.tunnel"
    assert f.severity is Severity.HIGH
    assert f.attack_technique == "T1071.004"
    assert f.src == CLIENT
    assert f.evidence["domain"] == "example.net"
    assert f.evidence["unique_subdomains"] == 40
    assert f.evidence["query_types"] == {"TXT": 40}
    assert f.evidence["mean_entropy_bits_per_char"] > 3.0
    assert len(f.evidence["sample_queries"]) == 10


def test_detects_hex_encoded_text_tunnel(write_pcap):
    # Hex-encoded *text* has lower entropy (~3.3 bits/char) than random hex (~3.9),
    # because only some nibble pairs occur. Regression test for a 3.5 threshold
    # that missed this case.
    data = ("Quarterly payroll export: employee ids, salaries and bank details. " * 12).encode()
    chunks = [data[i : i + 16].hex() for i in range(0, len(data), 16)]
    pkts = [dns_query(f"{i:02x}{c}.x.example.net", T0 + i) for i, c in enumerate(chunks)]
    (f,) = run(write_pcap, pkts)
    assert f.detector == "dns.tunnel"
    assert 3.0 <= f.evidence["mean_entropy_bits_per_char"] < 3.5


def test_normal_browsing_is_not_flagged(write_pcap):
    assert run(write_pcap, browsing_traffic()) == []


def test_many_short_low_entropy_subdomains_not_flagged(write_pcap):
    # e.g. host001..host030 under one zone: many unique names, but short and regular
    pkts = [dns_query(f"host{i:03d}.corp.example", T0 + i) for i in range(30)]
    assert run(write_pcap, pkts) == []


def test_tunnel_below_unique_threshold(write_pcap):
    assert run(write_pcap, tunnel_traffic(count=10)) == []


def test_tunnel_threshold_is_configurable(write_pcap):
    assert len(run(write_pcap, tunnel_traffic(count=10), tunnel_min_unique_subdomains=10)) == 1


def test_repeated_identical_queries_count_once(write_pcap):
    pkts = [dns_query(f"{hex_chunk(1)}.t.example.net", T0 + i) for i in range(50)]
    assert run(write_pcap, pkts) == []


# --- NXDOMAIN / DGA ------------------------------------------------------------


def dga_traffic(count=20):
    pkts = []
    for i in range(count):
        name = f"{hex_chunk(i, 12)}.com"
        pkts += [dns_query(name, T0 + i), dns_reply(name, T0 + i + 0.01, rcode=3)]
    return pkts


def test_detects_high_nxdomain_rate(write_pcap):
    (f,) = run(write_pcap, dga_traffic())
    assert f.detector == "dns.nxdomain"
    assert f.attack_technique == "T1568.002"
    assert f.src == CLIENT
    assert f.evidence["distinct_nxdomain_names"] == 20
    assert f.evidence["nxdomain_ratio"] == 1.0
    assert f.evidence["distinct_registered_domains"] == 20


def test_nxdomain_diluted_by_successful_lookups_not_flagged(write_pcap):
    # 12 NXDOMAIN among 72 replies (17%) - below the 50% ratio
    assert run(write_pcap, dga_traffic(12) + browsing_traffic()) == []


def test_few_nxdomains_not_flagged(write_pcap):
    assert run(write_pcap, dga_traffic(5)) == []


# --- misc ----------------------------------------------------------------------


def test_findings_serialise_and_sort(write_pcap):
    findings = run(write_pcap, dga_traffic() + tunnel_traffic())
    # tunnel starts with the first query at T0, NXDOMAIN with the first reply at T0 + 0.01
    assert [f.detector for f in findings] == ["dns.tunnel", "dns.nxdomain"]
    json.dumps([f.to_dict() for f in findings])


@pytest.mark.parametrize(
    "kwargs",
    [
        {"tunnel_min_unique_subdomains": 1},
        {"nx_min_distinct": 0},
        {"nx_min_ratio": 0},
        {"nx_min_ratio": 1.5},
        {"tunnel_min_mean_entropy": -1},
    ],
)
def test_invalid_config_rejected(kwargs):
    with pytest.raises(ValueError):
        DnsConfig(**kwargs)
