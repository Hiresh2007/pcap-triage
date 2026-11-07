import pytest

from pcap_triage.detectors import PortScanConfig, Severity, detect_port_scans
from pcap_triage.detectors.base import max_distinct_in_window
from pcap_triage.reader import read_packets

from .conftest import SCANNER, T0, TARGET, handshake, tcp, vertical_scan


def run(write_pcap, packets, **cfg):
    records, _ = read_packets(write_pcap(packets))
    return detect_port_scans(records, PortScanConfig(**cfg))


# --- sliding window helper -------------------------------------------------


def test_window_counts_distinct_values_once():
    events = [(0.0, 80), (0.1, 80), (0.2, 443), (0.3, 80)]
    best = max_distinct_in_window(events, window=10)
    assert best.distinct == 2
    assert best.values == {80, 443}


def test_window_slides_and_drops_old_events():
    # one new port every 10s; a 25s window can hold at most 3 events
    events = [(i * 10.0, port) for i, port in enumerate(range(1, 11))]
    best = max_distinct_in_window(events, window=25)
    assert best.distinct == 3
    assert best.end - best.start <= 25


def test_window_handles_unsorted_input_and_empty():
    assert max_distinct_in_window([], 5) is None
    best = max_distinct_in_window([(5.0, "b"), (0.0, "a"), (1.0, "c")], window=2)
    assert best.distinct == 2  # a@0 and c@1


# --- vertical scans --------------------------------------------------------


def test_detects_fast_vertical_scan_and_reports_open_ports(write_pcap):
    ports = list(range(20, 45))  # 25 ports
    findings = run(write_pcap, vertical_scan(ports, open_ports={22, 25}))

    vertical = [f for f in findings if f.detector == "portscan.vertical"]
    assert len(vertical) == 1
    f = vertical[0]
    assert (f.src, f.dst) == (SCANNER, TARGET)
    assert f.severity is Severity.MEDIUM
    assert f.attack_technique == "T1046"
    assert f.evidence["distinct_ports_in_window"] == 25
    assert f.evidence["open_ports"] == [22, 25]
    assert f.evidence["closed_port_count"] == 23


def test_no_finding_below_port_threshold(write_pcap):
    assert run(write_pcap, vertical_scan(range(1, 10))) == []  # 9 ports < 15


def test_threshold_is_inclusive(write_pcap):
    findings = run(write_pcap, vertical_scan(range(1, 16)))  # exactly 15 ports
    assert [f.detector for f in findings] == ["portscan.vertical"]


def test_slow_scan_outside_window_is_not_flagged(write_pcap):
    # 30 ports, one every 10 s -> at most 7 distinct ports in any 60 s window
    assert run(write_pcap, vertical_scan(range(1, 31), step=10.0)) == []


def test_slow_scan_flagged_with_wider_window(write_pcap):
    findings = run(write_pcap, vertical_scan(range(1, 31), step=10.0), window_seconds=600)
    assert len(findings) == 1


def test_synack_and_rst_traffic_alone_is_not_a_scan(write_pcap):
    # backscatter: many replies, no SYNs from the observed source
    pkts = [tcp(TARGET, SCANNER, port, 40000, "SA", T0 + port * 0.01) for port in range(1, 50)]
    assert run(write_pcap, pkts) == []


def test_normal_client_sessions_are_not_flagged(write_pcap):
    pkts = []
    for i in range(30):  # 30 connections, but only to two service ports
        pkts += handshake("192.0.2.5", TARGET, 50000 + i, 443 if i % 2 else 80, T0 + i * 0.5)
    assert run(write_pcap, pkts) == []


# --- horizontal sweeps -----------------------------------------------------


def test_detects_horizontal_sweep(write_pcap):
    hosts = [f"198.51.100.{i}" for i in range(1, 13)]
    pkts = [tcp(SCANNER, h, 40000, 445, "S", T0 + i * 0.05) for i, h in enumerate(hosts)]
    pkts.append(tcp(hosts[3], SCANNER, 445, 40000, "SA", T0 + 1))

    findings = run(write_pcap, pkts)
    assert len(findings) == 1
    f = findings[0]
    assert f.detector == "portscan.horizontal"
    assert f.dst is None
    assert f.evidence["port"] == 445
    assert f.evidence["distinct_hosts_in_window"] == 12
    assert f.evidence["hosts_with_port_open"] == [hosts[3]]


def test_findings_are_json_serialisable(write_pcap):
    import json

    findings = run(write_pcap, vertical_scan(range(1, 20)))
    json.dumps([f.to_dict() for f in findings])


# --- configuration ---------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [{"vertical_port_threshold": 1}, {"horizontal_host_threshold": 0}, {"window_seconds": 0}],
)
def test_invalid_config_rejected(kwargs):
    with pytest.raises(ValueError):
        PortScanConfig(**kwargs)
