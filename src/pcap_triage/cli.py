"""Command-line entry point: ``pcap-triage analyze capture.pcap``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from scapy.error import Scapy_Exception

from . import __version__
from .detectors import (
    BeaconConfig,
    DnsConfig,
    PortScanConfig,
    detect_beaconing,
    detect_dns_anomalies,
    detect_port_scans,
)
from .flows import summarize
from .reader import read_packets
from .report import AnalysisResult, render_json, render_text

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_DEFAULTS = PortScanConfig()
_DNS_DEFAULTS = DnsConfig()
_BEACON_DEFAULTS = BeaconConfig()


def analyze(
    path: Path,
    scan_config: PortScanConfig,
    dns_config: DnsConfig | None = None,
    beacon_config: BeaconConfig | None = None,
) -> AnalysisResult:
    records, stats = read_packets(path)
    findings = (
        detect_port_scans(records, scan_config)
        + detect_dns_anomalies(records, dns_config)
        + detect_beaconing(records, beacon_config)
    )
    findings.sort(key=lambda f: (f.first_seen, f.detector, f.src))
    return AnalysisResult(
        source=path.name,
        stats=stats,
        summary=summarize(records),
        findings=findings,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcap-triage", description="Offline PCAP triage for SOC analysis."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="summarise a capture and run detectors")
    a.add_argument("pcap", type=Path, help="path to a .pcap or .pcapng file")
    a.add_argument("--format", choices=["text", "json"], default="text")
    a.add_argument("--top", type=int, default=5, help="rows in top-N tables (default 5)")
    a.add_argument(
        "--scan-ports",
        type=int,
        default=_DEFAULTS.vertical_port_threshold,
        help="distinct ports on one host that count as a vertical scan",
    )
    a.add_argument(
        "--scan-hosts",
        type=int,
        default=_DEFAULTS.horizontal_host_threshold,
        help="distinct hosts on one port that count as a horizontal sweep",
    )
    a.add_argument(
        "--scan-window",
        type=float,
        default=_DEFAULTS.window_seconds,
        help="sliding window in seconds for scan detection",
    )
    a.add_argument(
        "--dns-min-subdomains",
        type=int,
        default=_DNS_DEFAULTS.tunnel_min_unique_subdomains,
        help="unique subdomains of one domain that count as possible DNS tunnelling",
    )
    a.add_argument(
        "--dns-min-nxdomain",
        type=int,
        default=_DNS_DEFAULTS.nx_min_distinct,
        help="distinct NXDOMAIN names for one client that count as possible DGA activity",
    )
    a.add_argument(
        "--beacon-min-events",
        type=int,
        default=_BEACON_DEFAULTS.min_events,
        help="check-ins on one channel needed before beaconing is considered",
    )
    a.add_argument(
        "--beacon-max-jitter",
        type=float,
        default=_BEACON_DEFAULTS.max_jitter,
        help="maximum interval jitter (median absolute deviation / median), e.g. 0.2",
    )
    a.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="exit with status 1 if any finding is produced (for CI / scripting)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.pcap.is_file():
        print(f"error: no such file: {args.pcap}", file=sys.stderr)
        return EXIT_ERROR
    try:
        config = PortScanConfig(args.scan_ports, args.scan_hosts, args.scan_window)
        dns_config = DnsConfig(
            tunnel_min_unique_subdomains=args.dns_min_subdomains,
            nx_min_distinct=args.dns_min_nxdomain,
        )
        beacon_config = BeaconConfig(
            min_events=args.beacon_min_events, max_jitter=args.beacon_max_jitter
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    try:
        result = analyze(args.pcap, config, dns_config, beacon_config)
    except (Scapy_Exception, OSError, EOFError) as exc:
        print(f"error: could not read {args.pcap}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    render = render_json if args.format == "json" else render_text
    print(render(result, top=args.top))
    if args.fail_on_findings and result.findings:
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
