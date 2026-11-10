"""DNS anomaly detection.

Two detectors, both computed over the whole capture:

* **DNS tunnelling** (MITRE ATT&CK T1071.004, Application Layer Protocol: DNS).
  Tools such as iodine or dnscat2 encode data into subdomain labels, so one
  client sends many *unique*, *long*, *high-entropy* names under a single
  domain the attacker controls, e.g. ``4a6f686e...3a.t.example.net``.

* **Domain generation algorithm (DGA) activity** (T1568.002). Malware that
  generates candidate C2 domains tries many of them before one resolves, so the
  client receives an unusually high number and share of NXDOMAIN replies.

Known false-positive sources: anti-virus / reputation services and DNS
blocklists that encode lookups into names (e.g. reversed IPs under a DNSBL
zone), CDN and telemetry hostnames, and misconfigured search domains, which
produce bursts of NXDOMAIN. Thresholds are tunable.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..reader import PacketRecord
from .base import Finding, Severity

NXDOMAIN = 3
SAMPLE_LIMIT = 10
QTYPE_NAMES = {1: "A", 5: "CNAME", 10: "NULL", 15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"}

# Second-level public suffixes common enough to matter for "registered domain".
# A full Public Suffix List is a later improvement (see docs/DESIGN.md).
_TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "net.in",
    "org.in", "ac.in", "co.jp", "co.nz", "com.br", "com.cn", "com.mx", "co.za", "com.tr",
}  # fmt: skip


@dataclass(frozen=True, slots=True)
class DnsConfig:
    tunnel_min_unique_subdomains: int = 15
    tunnel_min_mean_length: float = 20.0  # characters in the subdomain part
    tunnel_min_mean_entropy: float = 3.0  # Shannon bits per character; see DESIGN.md
    nx_min_distinct: int = 10  # distinct names answered NXDOMAIN
    nx_min_ratio: float = 0.5  # NXDOMAIN share of all replies to the client

    def __post_init__(self) -> None:
        if self.tunnel_min_unique_subdomains < 2 or self.nx_min_distinct < 2:
            raise ValueError("DNS count thresholds must be at least 2")
        if not 0 < self.nx_min_ratio <= 1:
            raise ValueError("nx_min_ratio must be in (0, 1]")
        if self.tunnel_min_mean_length < 0 or self.tunnel_min_mean_entropy < 0:
            raise ValueError("DNS length/entropy thresholds must be non-negative")


def shannon_entropy(text: str) -> float:
    """Bits per character of ``text``: 0 for 'aaaa', 4 for 16 equally used symbols."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def split_name(qname: str) -> tuple[str, str]:
    """Split a query name into (subdomain, registered domain).

    ``a1b2.t.example.co.uk`` -> (``a1b2.t``, ``example.co.uk``). Names with no
    subdomain return an empty first element.
    """
    labels = [label for label in qname.split(".") if label]
    keep = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES else 2
    if len(labels) <= keep:
        return "", ".".join(labels)
    return ".".join(labels[:-keep]), ".".join(labels[-keep:])


@dataclass(slots=True)
class _TunnelStats:
    first: float
    last: float
    queries: int = 0
    subdomains: set[str] = field(default_factory=set)
    qtypes: Counter = field(default_factory=Counter)


@dataclass(slots=True)
class _NxStats:
    first: float
    last: float
    replies: int = 0
    nx_names: set[str] = field(default_factory=set)
    nx_replies: int = 0


def detect_dns_anomalies(
    records: Iterable[PacketRecord], config: DnsConfig | None = None
) -> list[Finding]:
    config = config or DnsConfig()
    tunnels: dict[tuple[str, str], _TunnelStats] = {}
    nx: dict[str, _NxStats] = {}

    for r in records:
        if r.dns is None or not r.dns.qname:
            continue
        if not r.dns.is_response:
            sub, base = split_name(r.dns.qname)
            if not sub:
                continue
            t = tunnels.get((r.src, base))
            if t is None:
                t = tunnels[(r.src, base)] = _TunnelStats(r.ts, r.ts)
            t.first, t.last = min(t.first, r.ts), max(t.last, r.ts)
            t.queries += 1
            t.subdomains.add(sub)
            t.qtypes[QTYPE_NAMES.get(r.dns.qtype, str(r.dns.qtype))] += 1
        else:
            s = nx.get(r.dst)  # the client is the destination of the reply
            if s is None:
                s = nx[r.dst] = _NxStats(r.ts, r.ts)
            s.first, s.last = min(s.first, r.ts), max(s.last, r.ts)
            s.replies += 1
            if r.dns.rcode == NXDOMAIN:
                s.nx_replies += 1
                s.nx_names.add(r.dns.qname)

    findings = [f for key, t in tunnels.items() if (f := _tunnel_finding(*key, t, config))]
    findings += [f for client, s in nx.items() if (f := _nx_finding(client, s, config))]
    findings.sort(key=lambda f: (f.first_seen, f.detector, f.src))
    return findings


def _tunnel_finding(client: str, base: str, t: _TunnelStats, cfg: DnsConfig) -> Finding | None:
    unique = len(t.subdomains)
    if unique < cfg.tunnel_min_unique_subdomains:
        return None
    labels = [s.replace(".", "") for s in t.subdomains]
    mean_len = sum(map(len, labels)) / unique
    mean_entropy = sum(map(shannon_entropy, labels)) / unique
    if mean_len < cfg.tunnel_min_mean_length or mean_entropy < cfg.tunnel_min_mean_entropy:
        return None
    return Finding(
        detector="dns.tunnel",
        title=f"Possible DNS tunnelling via {base}",
        severity=Severity.HIGH,
        src=client,
        dst=None,
        first_seen=t.first,
        last_seen=t.last,
        description=(
            f"{client} queried {unique} unique subdomains of {base} "
            f"(mean length {mean_len:.1f}, mean entropy {mean_entropy:.2f} bits/char)."
        ),
        attack_technique="T1071.004",
        evidence={
            "domain": base,
            "queries": t.queries,
            "unique_subdomains": unique,
            "mean_subdomain_length": round(mean_len, 1),
            "mean_entropy_bits_per_char": round(mean_entropy, 2),
            "encoded_bytes_estimate": sum(map(len, labels)),
            "query_types": dict(t.qtypes.most_common()),
            "sample_queries": [f"{s}.{base}" for s in sorted(t.subdomains)[:SAMPLE_LIMIT]],
        },
    )


def _nx_finding(client: str, s: _NxStats, cfg: DnsConfig) -> Finding | None:
    distinct = len(s.nx_names)
    ratio = s.nx_replies / s.replies if s.replies else 0.0
    if distinct < cfg.nx_min_distinct or ratio < cfg.nx_min_ratio:
        return None
    bases = {split_name(n)[1] for n in s.nx_names}
    return Finding(
        detector="dns.nxdomain",
        title="High NXDOMAIN rate (possible DGA)",
        severity=Severity.MEDIUM,
        src=client,
        dst=None,
        first_seen=s.first,
        last_seen=s.last,
        description=(
            f"{client} received NXDOMAIN for {distinct} distinct names "
            f"({ratio:.0%} of {s.replies} DNS replies)."
        ),
        attack_technique="T1568.002",
        evidence={
            "nxdomain_replies": s.nx_replies,
            "total_replies": s.replies,
            "nxdomain_ratio": round(ratio, 3),
            "distinct_nxdomain_names": distinct,
            "distinct_registered_domains": len(bases),
            "sample_names": sorted(s.nx_names)[:SAMPLE_LIMIT],
        },
    )
