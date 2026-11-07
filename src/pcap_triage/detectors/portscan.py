"""TCP port-scan detection (MITRE ATT&CK T1046, Network Service Discovery).

Two patterns are detected from initial SYN packets (SYN set, ACK clear):

* **Vertical scan** - one source probes many distinct TCP ports on one target
  inside a short time window (``nmap -sS host``).
* **Horizontal sweep** - one source probes the same TCP port on many distinct
  hosts inside a short window (``nmap -p 445 10.0.0.0/24``).

For vertical scans the detector also reports which probed ports answered with
SYN-ACK (open) or RST (closed), because that tells an analyst what the
scanner learned.

Known false-positive sources: NAT gateways and proxies that aggregate many
users behind one address, vulnerability scanners you run yourself, and
protocols that negotiate dynamic ports (passive FTP, MS-RPC). Tune the
thresholds or allow-list those sources.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from ..reader import PacketRecord
from .base import Finding, Severity, max_distinct_in_window

PORT_SAMPLE_LIMIT = 25


@dataclass(frozen=True, slots=True)
class PortScanConfig:
    vertical_port_threshold: int = 15  # distinct ports on one host
    horizontal_host_threshold: int = 10  # distinct hosts on one port
    window_seconds: float = 60.0

    def __post_init__(self) -> None:
        if self.vertical_port_threshold < 2 or self.horizontal_host_threshold < 2:
            raise ValueError("scan thresholds must be at least 2")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")


def detect_port_scans(
    records: Iterable[PacketRecord], config: PortScanConfig | None = None
) -> list[Finding]:
    config = config or PortScanConfig()

    # (scanner, target) -> [(ts, dport)]
    vertical: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    # (scanner, dport) -> [(ts, target)]
    horizontal: dict[tuple[str, int], list[tuple[float, str]]] = defaultdict(list)
    # (target, scanner) -> ports that replied with SYN-ACK / RST
    replied_open: dict[tuple[str, str], set[int]] = defaultdict(set)
    replied_closed: dict[tuple[str, str], set[int]] = defaultdict(set)

    for r in records:
        if r.proto != "TCP" or r.sport is None or r.dport is None:
            continue
        if r.is_syn_only:
            vertical[(r.src, r.dst)].append((r.ts, r.dport))
            horizontal[(r.src, r.dport)].append((r.ts, r.dst))
        elif r.is_syn_ack:
            replied_open[(r.src, r.dst)].add(r.sport)
        elif r.is_rst:
            replied_closed[(r.src, r.dst)].add(r.sport)

    findings: list[Finding] = []

    for (scanner, target), events in vertical.items():
        best = max_distinct_in_window(events, config.window_seconds)
        if best is None or best.distinct < config.vertical_port_threshold:
            continue
        probed = {port for _, port in events}
        open_ports = sorted(replied_open[(target, scanner)] & probed)
        closed_ports = sorted((replied_closed[(target, scanner)] & probed) - set(open_ports))
        findings.append(
            Finding(
                detector="portscan.vertical",
                title="TCP vertical port scan",
                severity=Severity.MEDIUM,
                src=scanner,
                dst=target,
                first_seen=min(ts for ts, _ in events),
                last_seen=max(ts for ts, _ in events),
                description=(
                    f"{scanner} sent SYNs to {best.distinct} distinct ports on {target} "
                    f"within {best.end - best.start:.1f}s "
                    f"(threshold {config.vertical_port_threshold} in {config.window_seconds:g}s)."
                ),
                attack_technique="T1046",
                evidence={
                    "distinct_ports_in_window": best.distinct,
                    "window_start": best.start,
                    "window_end": best.end,
                    "total_distinct_ports": len(probed),
                    "syn_packets": len(events),
                    "port_sample": sorted(probed)[:PORT_SAMPLE_LIMIT],
                    "open_ports": open_ports,
                    "closed_port_count": len(closed_ports),
                },
            )
        )

    for (scanner, port), events in horizontal.items():
        best = max_distinct_in_window(events, config.window_seconds)
        if best is None or best.distinct < config.horizontal_host_threshold:
            continue
        hosts = sorted({host for _, host in events})
        responders = sorted(h for h in hosts if port in replied_open[(h, scanner)])
        findings.append(
            Finding(
                detector="portscan.horizontal",
                title=f"TCP horizontal sweep on port {port}",
                severity=Severity.MEDIUM,
                src=scanner,
                dst=None,
                first_seen=min(ts for ts, _ in events),
                last_seen=max(ts for ts, _ in events),
                description=(
                    f"{scanner} sent SYNs to port {port} on {best.distinct} distinct hosts "
                    f"within {best.end - best.start:.1f}s "
                    f"(threshold {config.horizontal_host_threshold} in {config.window_seconds:g}s)."
                ),
                attack_technique="T1046",
                evidence={
                    "port": port,
                    "distinct_hosts_in_window": best.distinct,
                    "window_start": best.start,
                    "window_end": best.end,
                    "total_distinct_hosts": len(hosts),
                    "host_sample": hosts[:PORT_SAMPLE_LIMIT],
                    "hosts_with_port_open": responders,
                },
            )
        )

    findings.sort(key=lambda f: (f.first_seen, f.detector, f.src))
    return findings
