"""Shared types for detectors."""

from __future__ import annotations

from collections import Counter
from collections.abc import Hashable, Sequence
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(slots=True)
class Finding:
    """A single detection result. ``evidence`` must be JSON-serialisable."""

    detector: str
    title: str
    severity: Severity
    src: str
    dst: str | None
    first_seen: float
    last_seen: float
    description: str
    attack_technique: str | None = None  # MITRE ATT&CK technique ID, e.g. "T1046"
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass(frozen=True, slots=True)
class WindowResult:
    distinct: int
    start: float
    end: float
    values: frozenset


def max_distinct_in_window(
    events: Sequence[tuple[float, Hashable]], window: float
) -> WindowResult | None:
    """Return the time window of length ``window`` containing the most distinct values.

    ``events`` are ``(timestamp, value)`` pairs. A two-pointer sweep keeps a
    counter of the values inside the current window, so the whole search is
    O(n log n) for the sort plus O(n) for the sweep. Repeated values (for
    example a retransmitted SYN to the same port) count once.
    """
    if not events:
        return None
    ordered = sorted(events, key=lambda e: e[0])
    in_window: Counter = Counter()
    best: WindowResult | None = None
    left = 0
    for ts, value in ordered:
        in_window[value] += 1
        while ts - ordered[left][0] > window:
            old = ordered[left][1]
            in_window[old] -= 1
            if in_window[old] == 0:
                del in_window[old]
            left += 1
        if best is None or len(in_window) > best.distinct:
            best = WindowResult(len(in_window), ordered[left][0], ts, frozenset(in_window))
    return best
