"""Read packet captures into small, protocol-agnostic records.

Scapy packet objects are large and slow to keep around. The reader streams the
capture once and converts every IPv4/IPv6 packet into a ``PacketRecord`` that
holds only the fields the analysis stages need. Non-IP frames (ARP, STP, ...)
are counted but not converted yet.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

# TCP flag bits as defined in RFC 793 / RFC 3168.
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20


DNS_PORT = 53


def _printable_name(raw: bytes) -> str:
    r"""Decode a DNS name for display, escaping bytes outside printable ASCII as \xNN.

    Labels may contain arbitrary bytes, so an unescaped name could inject
    terminal control sequences (e.g. ESC [ 31 m) into text reports.
    """
    return "".join(chr(b) if 0x21 <= b <= 0x7E else f"\\x{b:02x}" for b in raw)


@dataclass(frozen=True, slots=True)
class DnsInfo:
    """The parts of a DNS message used by the DNS detectors (first question only)."""

    qname: str  # lower-case, no trailing dot
    qtype: int  # 1=A, 16=TXT, 28=AAAA, ...
    is_response: bool
    rcode: int  # 0=NOERROR, 3=NXDOMAIN


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """One IP packet reduced to the fields used by flow analysis and detectors."""

    ts: float
    src: str
    dst: str
    proto: str  # "TCP", "UDP", "ICMP" or "OTHER"
    length: int
    sport: int | None = None
    dport: int | None = None
    tcp_flags: int = 0
    dns: DnsInfo | None = None

    @property
    def is_syn_only(self) -> bool:
        """True for an initial connection attempt (SYN set, ACK clear)."""
        return self.proto == "TCP" and bool(self.tcp_flags & SYN) and not self.tcp_flags & ACK

    @property
    def is_syn_ack(self) -> bool:
        return self.proto == "TCP" and (self.tcp_flags & (SYN | ACK)) == (SYN | ACK)

    @property
    def is_rst(self) -> bool:
        return self.proto == "TCP" and bool(self.tcp_flags & RST)


@dataclass(slots=True)
class ReadStats:
    """Counters describing what the reader saw, including skipped frames."""

    total_frames: int = 0
    ip_packets: int = 0
    non_ip_frames: int = 0


def _dns_info(pkt) -> DnsInfo | None:
    """Extract the first question of a DNS message; None if absent or malformed.

    Captures routinely contain truncated or non-DNS payloads on port 53, so any
    parsing problem results in None rather than an exception.
    """
    if DNS not in pkt:
        return None
    try:
        dns = pkt[DNS]
        qd = dns.qd
        question = qd[0] if isinstance(qd, list) else qd
        if question is None:
            return None
        raw = question.qname
        name = _printable_name(raw if isinstance(raw, bytes) else str(raw).encode())
        return DnsInfo(
            qname=name.rstrip(".").lower(),
            qtype=int(question.qtype),
            is_response=bool(dns.qr),
            rcode=int(dns.rcode),
        )
    except (AttributeError, IndexError, TypeError, ValueError):
        return None


def _to_record(pkt) -> PacketRecord | None:
    if IP in pkt:
        ip = pkt[IP]
    elif IPv6 in pkt:
        ip = pkt[IPv6]
    else:
        return None

    ts = float(pkt.time)
    length = len(pkt)
    if TCP in pkt:
        tcp = pkt[TCP]
        return PacketRecord(ts, ip.src, ip.dst, "TCP", length, tcp.sport, tcp.dport, int(tcp.flags))
    if UDP in pkt:
        udp = pkt[UDP]
        dns = _dns_info(pkt) if DNS_PORT in (udp.sport, udp.dport) else None
        return PacketRecord(ts, ip.src, ip.dst, "UDP", length, udp.sport, udp.dport, dns=dns)
    if ICMP in pkt:
        return PacketRecord(ts, ip.src, ip.dst, "ICMP", length)
    return PacketRecord(ts, ip.src, ip.dst, "OTHER", length)


def iter_packets(path: str | Path, stats: ReadStats | None = None) -> Iterator[PacketRecord]:
    """Stream ``PacketRecord`` objects from a pcap or pcapng file.

    ``PcapReader`` detects pcap vs. pcapng from the file's magic number and
    reads packets lazily, so memory use does not grow with capture size.
    """
    stats = stats if stats is not None else ReadStats()
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            stats.total_frames += 1
            record = _to_record(pkt)
            if record is None:
                stats.non_ip_frames += 1
                continue
            stats.ip_packets += 1
            yield record


def read_packets(path: str | Path) -> tuple[list[PacketRecord], ReadStats]:
    """Read a whole capture into memory. Convenient for small and medium files."""
    stats = ReadStats()
    records = list(iter_packets(path, stats))
    return records, stats
