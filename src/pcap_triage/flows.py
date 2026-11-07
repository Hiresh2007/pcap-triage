"""Aggregate packets into flows and compute capture-level summary statistics.

A flow here is *directional*: packets from A:1234 -> B:80 and B:80 -> A:1234
are two flows. Keeping direction makes byte counts per side easy to read and
keeps the scan detector simple (it reasons about who initiated what).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from .reader import PacketRecord


@dataclass(frozen=True, slots=True)
class FlowKey:
    src: str
    sport: int | None
    dst: str
    dport: int | None
    proto: str

    def __str__(self) -> str:
        s = self.src if self.sport is None else f"{self.src}:{self.sport}"
        d = self.dst if self.dport is None else f"{self.dst}:{self.dport}"
        return f"{self.proto} {s} -> {d}"


@dataclass(slots=True)
class Flow:
    key: FlowKey
    packets: int = 0
    bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    tcp_flags_seen: int = 0

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen


@dataclass(slots=True)
class CaptureSummary:
    packets: int = 0
    bytes: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    protocols: Counter = field(default_factory=Counter)
    talkers_by_bytes: Counter = field(default_factory=Counter)
    flows: dict[FlowKey, Flow] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        if self.first_seen is None or self.last_seen is None:
            return 0.0
        return self.last_seen - self.first_seen

    def top_talkers(self, n: int = 5) -> list[tuple[str, int]]:
        return self.talkers_by_bytes.most_common(n)

    def top_flows(self, n: int = 5) -> list[Flow]:
        return sorted(self.flows.values(), key=lambda f: f.bytes, reverse=True)[:n]


def summarize(records: Iterable[PacketRecord]) -> CaptureSummary:
    """Single pass over the records building flows and capture counters."""
    summary = CaptureSummary()
    for r in records:
        summary.packets += 1
        summary.bytes += r.length
        summary.protocols[r.proto] += 1
        summary.talkers_by_bytes[r.src] += r.length
        if summary.first_seen is None or r.ts < summary.first_seen:
            summary.first_seen = r.ts
        if summary.last_seen is None or r.ts > summary.last_seen:
            summary.last_seen = r.ts

        key = FlowKey(r.src, r.sport, r.dst, r.dport, r.proto)
        flow = summary.flows.get(key)
        if flow is None:
            flow = Flow(key, first_seen=r.ts, last_seen=r.ts)
            summary.flows[key] = flow
        flow.packets += 1
        flow.bytes += r.length
        flow.first_seen = min(flow.first_seen, r.ts)
        flow.last_seen = max(flow.last_seen, r.ts)
        flow.tcp_flags_seen |= r.tcp_flags
    return summary
