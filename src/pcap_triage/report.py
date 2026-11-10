"""Render analysis results as human-readable text or machine-readable JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .detectors import Finding
from .flows import CaptureSummary
from .reader import ReadStats


@dataclass(slots=True)
class AnalysisResult:
    source: str
    stats: ReadStats
    summary: CaptureSummary
    findings: list[Finding]


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds")


def to_dict(result: AnalysisResult, top: int = 5) -> dict[str, Any]:
    s = result.summary
    return {
        "tool": {"name": "pcap-triage", "version": __version__},
        "source": result.source,
        "capture": {
            "frames": result.stats.total_frames,
            "ip_packets": result.stats.ip_packets,
            "non_ip_frames": result.stats.non_ip_frames,
            "bytes": s.bytes,
            "first_seen": _iso(s.first_seen),
            "last_seen": _iso(s.last_seen),
            "duration_seconds": round(s.duration, 6),
            "protocols": dict(s.protocols.most_common()),
            "flow_count": len(s.flows),
        },
        "top_talkers": [{"address": a, "bytes": b} for a, b in s.top_talkers(top)],
        "top_flows": [
            {
                "flow": str(f.key),
                "packets": f.packets,
                "bytes": f.bytes,
                "duration_seconds": round(f.duration, 6),
            }
            for f in s.top_flows(top)
        ],
        "findings": [
            {**f.to_dict(), "first_seen": _iso(f.first_seen), "last_seen": _iso(f.last_seen)}
            for f in result.findings
        ],
    }


def render_json(result: AnalysisResult, top: int = 5) -> str:
    return json.dumps(to_dict(result, top), indent=2)


def render_text(result: AnalysisResult, top: int = 5) -> str:
    d = to_dict(result, top)
    c = d["capture"]
    lines = [
        f"pcap-triage {__version__} - {d['source']}",
        "",
        "Capture",
        f"  frames        {c['frames']} ({c['ip_packets']} IP, {c['non_ip_frames']} non-IP)",
        f"  bytes         {c['bytes']}",
        f"  time range    {c['first_seen']} -> {c['last_seen']} ({c['duration_seconds']:.3f}s)",
        f"  flows         {c['flow_count']}",
        "  protocols     " + (", ".join(f"{p}={n}" for p, n in c["protocols"].items()) or "none"),
        "",
        "Top talkers (bytes sent)",
    ]
    lines += [f"  {t['address']:<40} {t['bytes']}" for t in d["top_talkers"]] or ["  none"]
    lines += ["", f"Findings ({len(d['findings'])})"]
    if not d["findings"]:
        lines.append("  none")
    for f in d["findings"]:
        technique = f" [{f['attack_technique']}]" if f["attack_technique"] else ""
        lines.append(f"  [{f['severity'].upper()}] {f['title']}{technique}")
        lines.append(f"      {f['description']}")
        if f["evidence"].get("open_ports"):
            lines.append(f"      open ports: {', '.join(map(str, f['evidence']['open_ports']))}")
        samples = f["evidence"].get("sample_queries") or f["evidence"].get("sample_names")
        if samples:
            lines.append("      e.g. " + ", ".join(samples[:3]))
        if f["evidence"].get("hosts_with_port_open"):
            lines.append(
                "      hosts with port open: " + ", ".join(f["evidence"]["hosts_with_port_open"])
            )
    return "\n".join(lines)
