"""Cleartext credential detection.

Flags logins sent without encryption, which anyone on the path can read
(the exposure that MITRE ATT&CK T1040, Network Sniffing, exploits):

* HTTP Basic: ``Authorization: Basic <base64(user:password)>`` on any port
* FTP and POP3: ``USER <name>`` / ``PASS <secret>`` commands (ports 21, 110)
* IMAP: ``<tag> LOGIN <name> <secret>`` (port 143)
* Telnet: client data sent to port 23 (keystrokes, including passwords, travel in
  clear). A bare SYN is not counted, so port scans that probe 23 are not sessions.

Secrets are never stored or reported: evidence holds the username and the
password *length* only. Usernames come from untrusted traffic and are escaped
like DNS names.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..reader import PacketRecord, _printable_name
from .base import Finding, Severity

_HTTP_BASIC = re.compile(rb"(?im)^authorization:[ \t]*basic[ \t]+([A-Za-z0-9+/=]+)")
_USER_PASS = re.compile(rb"(?i)^(USER|PASS) (\S+)")
_IMAP_LOGIN = re.compile(rb"(?i)^\S+ LOGIN (\S+) (\S+)")
_PORT_PROTO = {21: "FTP", 110: "POP3", 143: "IMAP", 23: "Telnet"}


@dataclass(slots=True)
class _Exposure:
    protocol: str
    first: float
    last: float
    logins: int = 0
    users: set[str] = field(default_factory=set)
    password_lengths: list[int] = field(default_factory=list)


def _clean(raw: bytes) -> str:
    return _printable_name(raw.strip().strip(b'"'))


def detect_cleartext_credentials(records: Iterable[PacketRecord]) -> list[Finding]:
    exposures: dict[tuple[str, str, int], _Exposure] = {}

    def hit(r: PacketRecord, proto: str, user: bytes | None = None, secret_len: int = 0):
        key = (r.src, r.dst, r.dport)
        e = exposures.get(key)
        if e is None:
            e = exposures[key] = _Exposure(proto, r.ts, r.ts)
        e.first, e.last = min(e.first, r.ts), max(e.last, r.ts)
        if user is not None:
            e.users.add(_clean(user))
        if secret_len:
            e.logins += 1
            e.password_lengths.append(secret_len)

    for r in records:
        if r.proto != "TCP" or r.dport is None:
            continue
        proto = _PORT_PROTO.get(r.dport)
        if not r.payload:
            continue
        if proto == "Telnet":
            hit(r, proto)
            continue
        if m := _HTTP_BASIC.search(r.payload):
            try:
                user, _, secret = base64.b64decode(m.group(1), validate=True).partition(b":")
            except (binascii.Error, ValueError):
                continue
            hit(r, "HTTP Basic", user, len(secret))
        elif proto in ("FTP", "POP3") and (m := _USER_PASS.match(r.payload)):
            if m.group(1).upper() == b"USER":
                hit(r, proto, m.group(2))
            else:
                hit(r, proto, secret_len=len(m.group(2)))
        elif proto == "IMAP" and (m := _IMAP_LOGIN.match(r.payload)):
            hit(r, proto, m.group(1), len(m.group(2).strip(b'"')))

    findings = []
    for (client, server, port), e in exposures.items():
        what = "session" if e.protocol == "Telnet" else "credentials"
        findings.append(
            Finding(
                detector="cleartext.credentials",
                title=f"Cleartext {e.protocol} {what}",
                severity=Severity.HIGH,
                src=client,
                dst=server,
                first_seen=e.first,
                last_seen=e.last,
                description=(
                    f"{client} sent {e.protocol} {what} to {server}:{port} without encryption"
                    + (f" ({e.logins} password(s) observed)." if e.logins else ".")
                ),
                attack_technique="T1040",
                evidence={
                    "protocol": e.protocol,
                    "port": port,
                    "usernames": sorted(e.users),
                    "passwords_observed": e.logins,
                    "password_lengths": e.password_lengths,  # never the secret itself
                },
            )
        )
    findings.sort(key=lambda f: (f.first_seen, f.src))
    return findings
