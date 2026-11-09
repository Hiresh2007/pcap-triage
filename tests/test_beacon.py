import json
import random

import pytest
from scapy.layers.inet import IP, UDP

from pcap_triage.detectors import BeaconConfig, detect_beaconing
from pcap_triage.detectors.beacon import event_starts, interval_stats
from pcap_triage.reader import read_packets

from .conftest import T0, eth, handshake, stamp

IMPLANT = "192.0.2.88"
C2 = "203.0.113.50"


def run(write_pcap, packets, **cfg):
    records, _ = read_packets(write_pcap(packets))
    return detect_beaconing(records, BeaconConfig(**cfg))


def beacon_times(n, interval, jitter=0.0, seed=1, start=T0):
    """Check-in times every `interval` s with uniform +/- jitter (fraction of interval)."""
    rng = random.Random(seed)  # noqa: S311 - deterministic test data
    times, t = [], start
    for _ in range(n):
        times.append(t)
        t += interval * (1 + rng.uniform(-jitter, jitter))
    return times


def tcp_checkins(times, src=IMPLANT, dst=C2, port=443):
    pkts = []
    for i, ts in enumerate(times):
        pkts += handshake(src, dst, 50000 + i, port, ts)  # new connection each check-in
    return pkts


def udp_checkins(times, src=IMPLANT, dst=C2, port=4444, sport=51515):
    pkts = []
    for ts in times:
        out = IP(src=src, dst=dst) / UDP(sport=sport, dport=port) / b"ping"
        back = IP(src=dst, dst=src) / UDP(sport=port, dport=sport) / b"pong"
        pkts += [stamp(eth() / out, ts), stamp(eth() / back, ts + 0.05)]
    return pkts


# --- statistics helpers --------------------------------------------------------


def test_event_starts_merges_bursts():
    assert event_starts([0, 0.5, 1.0, 10, 10.1, 30], burst_gap=2) == [0, 10, 30]


def test_interval_stats_perfect_and_irregular():
    perfect = interval_stats([0, 60, 120, 180, 240])
    assert perfect.median_interval == 60 and perfect.jitter == 0
    irregular = interval_stats([0, 5, 100, 110, 400])
    assert irregular.jitter > 0.5
    assert interval_stats([5.0]) is None


def test_one_missed_beacon_barely_moves_robust_stats():
    times = [i * 60.0 for i in range(12) if i != 6]  # check-in 6 lost
    stats = interval_stats(times)
    assert stats.median_interval == 60 and stats.jitter == 0


# --- detection ---------------------------------------------------------------------


def test_detects_regular_tcp_beacon(write_pcap):
    (f,) = run(write_pcap, tcp_checkins(beacon_times(12, 60)))
    assert f.detector == "beacon"
    assert f.attack_technique == "T1071"
    assert (f.src, f.dst) == (IMPLANT, C2)
    assert f.evidence["port"] == 443
    assert f.evidence["events"] == 12
    assert f.evidence["median_interval_seconds"] == pytest.approx(60, abs=0.01)
    assert f.evidence["jitter_mad_ratio"] < 0.01


@pytest.mark.parametrize("jitter", [0.1, 0.2, 0.3])
def test_detects_jittered_beacon(write_pcap, jitter):
    # uniform +/-30 % jitter has a MAD of about 15 % of the interval
    (f,) = run(write_pcap, tcp_checkins(beacon_times(20, 45, jitter=jitter, seed=7)))
    assert f.evidence["jitter_mad_ratio"] <= 0.2


def test_detects_udp_beacon_and_ignores_replies(write_pcap):
    findings = run(write_pcap, udp_checkins(beacon_times(10, 30)))
    assert [(f.src, f.dst, f.evidence["port"]) for f in findings] == [(IMPLANT, C2, 4444)]


def test_human_like_irregular_traffic_not_flagged(write_pcap):
    rng = random.Random(3)  # noqa: S311 - deterministic test data
    times, t = [], T0
    for _ in range(40):  # exponential gaps: browsing-like, mean 60 s
        times.append(t)
        t += rng.expovariate(1 / 60) + 5
    assert run(write_pcap, tcp_checkins(times)) == []


def test_too_few_events_not_flagged(write_pcap):
    assert run(write_pcap, tcp_checkins(beacon_times(6, 60))) == []


def test_fast_repetition_is_not_beaconing(write_pcap):
    # a client polling every second is a session, not a beacon (min_interval 5 s)
    assert run(write_pcap, tcp_checkins(beacon_times(30, 1))) == []


def test_multi_packet_checkins_count_once(write_pcap):
    times = beacon_times(10, 60)
    pkts = tcp_checkins(times) + tcp_checkins([t + 0.3 for t in times])  # 2 conns per check-in
    (f,) = run(write_pcap, pkts)
    assert f.evidence["events"] == 10


def test_ntp_and_dns_ports_ignored_by_default(write_pcap):
    times = beacon_times(12, 64)
    pkts = udp_checkins(times, port=123, sport=40123) + udp_checkins(times, port=53, sport=40053)
    assert run(write_pcap, pkts) == []
    assert len(run(write_pcap, pkts, ignored_ports=frozenset())) == 2


def test_channels_are_independent(write_pcap):
    beacon = tcp_checkins(beacon_times(12, 60))
    other = tcp_checkins(beacon_times(12, 60, start=T0 + 7), dst="203.0.113.99", port=8443)
    findings = run(write_pcap, beacon + other)
    assert sorted(f.dst for f in findings) == [C2, "203.0.113.99"]
    json.dumps([f.to_dict() for f in findings])


@pytest.mark.parametrize(
    "kwargs",
    [{"min_events": 3}, {"max_jitter": 0}, {"max_jitter": 1}, {"burst_gap": 0},
     {"min_interval": -1}],
)  # fmt: skip
def test_invalid_config_rejected(kwargs):
    with pytest.raises(ValueError):
        BeaconConfig(**kwargs)
