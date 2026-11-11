"""Allow-lists: suppress findings for known-good activity, with a recorded reason.

File format (TOML), one ``[[allow]]`` table per rule. Every field except
``reason`` is optional; a rule matches a finding when *all* fields it sets
match. Suppressed findings are kept and reported separately, so an
allow-list can always be audited rather than silently hiding alerts.

    [[allow]]
    detector = "beacon"            # exact name or glob, e.g. "dns.*"
    src = "192.0.2.10"             # IP or CIDR
    dst = "203.0.113.0/24"         # IP or CIDR (findings without dst never match)
    port = 443                     # evidence["port"]
    domain = "example.com"         # evidence["domain"], including subdomains
    reason = "Monitoring agent heartbeat (ticket OPS-123)"
"""

from __future__ import annotations

import ipaddress
import sys
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from .detectors import Finding

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on Python 3.10 in CI
    import tomli as tomllib

_FIELDS = {"detector", "src", "dst", "port", "domain", "reason"}
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class AllowlistError(ValueError):
    """The allow-list file is missing, malformed or contains an invalid rule."""


@dataclass(frozen=True, slots=True)
class AllowRule:
    reason: str
    detector: str | None = None
    src: Network | None = None
    dst: Network | None = None
    port: int | None = None
    domain: str | None = None

    def matches(self, f: Finding) -> bool:
        if self.detector is not None and not fnmatchcase(f.detector, self.detector):
            return False
        if self.src is not None and not _in(f.src, self.src):
            return False
        if self.dst is not None and (f.dst is None or not _in(f.dst, self.dst)):
            return False
        if self.port is not None and f.evidence.get("port") != self.port:
            return False
        if self.domain is not None:
            d = str(f.evidence.get("domain", ""))
            if not (d == self.domain or d.endswith("." + self.domain)):
                return False
        return True


@dataclass(frozen=True, slots=True)
class Suppressed:
    finding: Finding
    reason: str


def _in(address: str, network: Network) -> bool:
    try:
        return ipaddress.ip_address(address) in network
    except ValueError:
        return False


def _network(value: object, where: str) -> Network:
    try:
        return ipaddress.ip_network(str(value), strict=False)
    except ValueError as exc:
        raise AllowlistError(f"{where}: invalid IP or CIDR {value!r}") from exc


def parse_rules(data: dict) -> list[AllowRule]:
    entries = data.get("allow", [])
    if not isinstance(entries, list):
        raise AllowlistError("'allow' must be an array of tables ([[allow]])")
    rules = []
    for i, entry in enumerate(entries, start=1):
        where = f"rule {i}"
        if not isinstance(entry, dict):
            raise AllowlistError(f"{where}: must be a table")
        unknown = set(entry) - _FIELDS
        if unknown:
            raise AllowlistError(f"{where}: unknown field(s) {', '.join(sorted(unknown))}")
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise AllowlistError(f"{where}: 'reason' is required")
        if len(entry) == 1:
            raise AllowlistError(f"{where}: needs at least one condition besides 'reason'")
        port = entry.get("port")
        if port is not None and (not isinstance(port, int) or not 0 <= port <= 65535):
            raise AllowlistError(f"{where}: port must be an integer 0-65535")
        rules.append(
            AllowRule(
                reason=reason.strip(),
                detector=entry.get("detector"),
                src=_network(entry["src"], where) if "src" in entry else None,
                dst=_network(entry["dst"], where) if "dst" in entry else None,
                port=port,
                domain=str(entry["domain"]).lower().rstrip(".") if "domain" in entry else None,
            )
        )
    return rules


def load_allowlist(path: str | Path) -> list[AllowRule]:
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise AllowlistError(f"cannot read allow-list {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise AllowlistError(f"invalid TOML in {path}: {exc}") from exc
    return parse_rules(data)


def apply_allowlist(
    findings: list[Finding], rules: list[AllowRule]
) -> tuple[list[Finding], list[Suppressed]]:
    """Split findings into (kept, suppressed); the first matching rule supplies the reason."""
    kept, suppressed = [], []
    for f in findings:
        rule = next((r for r in rules if r.matches(f)), None)
        if rule is None:
            kept.append(f)
        else:
            suppressed.append(Suppressed(f, rule.reason))
    return kept, suppressed
