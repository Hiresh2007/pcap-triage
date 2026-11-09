"""Beaconing detection (MITRE ATT&CK T1071, Application Layer Protocol).

Implants check in with their command-and-control server on a timer, e.g.
every 60 s with +/-20 % random jitter. Human-driven traffic is irregular.
The signal is therefore the *regularity* of contact between one source and
one destination service, not its volume.

Method, per channel (src, dst, dst port, protocol):

1. Collect *events* from the initiator: for TCP each new connection (SYN);
   for UDP each packet towards the lower-numbered (service) port. Events
   closer together than ``burst_gap`` seconds are merged, so a check-in that
   opens several connections or sends several datagrams counts once.
2. Take the intervals between consecutive event start times.
3. Typical interval = median; jitter = median absolute deviation / median.
   Both are robust: one missed or delayed beacon barely moves them, unlike
   mean and standard deviation.
4. Flag channels with at least ``min_events`` events and jitter at or below
   ``max_jitter``.

Limitations: beacons that reuse one long-lived TCP connection produce a
single SYN and are not seen; UDP services on a port higher than the
client's are mis-oriented.

Known false positives: NTP, monitoring agents and health checks, software
update polling, keep-alives of long-lived sessions (chat, push services).
DNS and NTP ports are skipped by default; other services need allow-lists.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from statistics import median

from ..reader import PacketRecord
from .base import Finding, Severity

DEFAULT_IGNORED_PORTS = frozenset({53, 123})  # DNS (has its own detector), NTP


@dataclass(frozen=True, slots=True)
class BeaconConfig:
    min_events: int = 8
    max_jitter: float = 0.2  # median absolute deviation / median interval
    burst_gap: float = 2.0  # seconds; closer packets belong to one event
    min_interval: float = 5.0  # seconds; faster repetition is a session, not a beacon
    ignored_ports: frozenset[int] = DEFAULT_IGNORED_PORTS

    def __post_init__(self) -> None:
        if self.min_events < 4:
            raise ValueError("min_events must be at least 4 (3 intervals)")
        if not 0 < self.max_jitter < 1:
            raise ValueError("max_jitter must be between 0 and 1")
        if self.burst_gap <= 0 or self.min_interval <= 0:
            raise ValueError("burst_gap and min_interval must be positive")


@dataclass(frozen=True, slots=True)
class IntervalStats:
    events: int
    median_interval: float
    jitter: float  # MAD / median


def event_starts(timestamps: Iterable[float], burst_gap: float) -> list[float]:
    """Collapse packet times into event start times (gap > burst_gap starts a new event)."""
    starts: list[float] = []
    last: float | None = None
    for ts in sorted(timestamps):
        if last is None or ts - last > burst_gap:
            starts.append(ts)
        last = ts
    return starts


def interval_stats(starts: list[float]) -> IntervalStats | None:
    if len(starts) < 2:
        return None
    intervals = [b - a for a, b in zip(starts, starts[1:], strict=False)]
    med = median(intervals)
    if med <= 0:
        return None
    mad = median(abs(i - med) for i in intervals)
    return IntervalStats(len(starts), med, mad / med)


def detect_beaconing(
    records: Iterable[PacketRecord], config: BeaconConfig | None = None
) -> list[Finding]:
    config = config or BeaconConfig()
    channels: dict[tuple[str, str, int, str], list[PacketRecord]] = defaultdict(list)
    for r in records:
        if r.proto not in ("TCP", "UDP") or r.dport is None:
            continue
        if r.dport in config.ignored_ports or r.sport in config.ignored_ports:
            continue
        if r.proto == "TCP":
            # an event is a new connection; the SYN identifies the initiator exactly
            if not r.is_syn_only:
                continue
        elif r.sport is not None and r.dport > r.sport:
            # UDP has no handshake: assume the client uses the higher (ephemeral)
            # port, so packets towards the higher port are replies
            continue
        channels[(r.src, r.dst, r.dport, r.proto)].append(r)

    findings = []
    for (src, dst, port, proto), pkts in channels.items():
        starts = event_starts((p.ts for p in pkts), config.burst_gap)
        if len(starts) < config.min_events:
            continue
        stats = interval_stats(starts)
        if stats is None or stats.median_interval < config.min_interval:
            continue
        if stats.jitter > config.max_jitter:
            continue
        total_bytes = sum(p.length for p in pkts)
        findings.append(
            Finding(
                detector="beacon",
                title=f"Periodic beaconing to {dst}:{port}/{proto.lower()}",
                severity=Severity.MEDIUM,
                src=src,
                dst=dst,
                first_seen=starts[0],
                last_seen=max(p.ts for p in pkts),
                description=(
                    f"{src} contacted {dst}:{port} {stats.events} times about every "
                    f"{stats.median_interval:.1f}s (jitter {stats.jitter:.0%})."
                ),
                attack_technique="T1071",
                evidence={
                    "port": port,
                    "protocol": proto,
                    "events": stats.events,
                    "median_interval_seconds": round(stats.median_interval, 3),
                    "jitter_mad_ratio": round(stats.jitter, 4),
                    "duration_seconds": round(starts[-1] - starts[0], 3),
                    "packets": len(pkts),
                    "mean_bytes_per_event": round(total_bytes / stats.events, 1),
                },
            )
        )
    findings.sort(key=lambda f: (f.first_seen, f.src, f.dst or ""))
    return findings
