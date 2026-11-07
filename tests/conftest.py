"""Helpers that build small synthetic captures with Scapy.

All traffic uses RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24)
so the fixtures never reference real hosts.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

SCANNER = "192.0.2.66"
TARGET = "198.51.100.10"
T0 = 1_700_000_000.0
# Locally administered MACs; explicit so Scapy never consults host interfaces.
MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"


def stamp(pkt, ts: float):
    pkt.time = ts
    return pkt


def eth(dst=MAC_B):
    return Ether(src=MAC_A, dst=dst)


def tcp(src, dst, sport, dport, flags, ts):
    return stamp(eth() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags), ts)


def vertical_scan(ports, start=T0, step=0.01, open_ports=()):
    """SYN to each port; target answers SYN-ACK for open ports and RST-ACK otherwise."""
    pkts = []
    for i, port in enumerate(ports):
        ts = start + i * step
        pkts.append(tcp(SCANNER, TARGET, 40000, port, "S", ts))
        reply = "SA" if port in open_ports else "RA"
        pkts.append(tcp(TARGET, SCANNER, port, 40000, reply, ts + step / 2))
    return pkts


def handshake(client, server, sport, dport, ts):
    return [
        tcp(client, server, sport, dport, "S", ts),
        tcp(server, client, dport, sport, "SA", ts + 0.01),
        tcp(client, server, sport, dport, "A", ts + 0.02),
    ]


@pytest.fixture
def write_pcap(tmp_path: Path):
    def _write(packets, name="capture.pcap") -> Path:
        path = tmp_path / name
        wrpcap(str(path), packets)
        return path

    return _write


CLIENT = "192.0.2.20"
RESOLVER = "192.0.2.53"


def dns_query(qname, ts, client=CLIENT, qtype="A", sport=53000):
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import UDP

    q = IP(src=client, dst=RESOLVER) / UDP(sport=sport, dport=53)
    return stamp(eth() / q / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype)), ts)


def dns_reply(qname, ts, client=CLIENT, rcode=0, dport=53000):
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import UDP

    r = IP(src=RESOLVER, dst=client) / UDP(sport=53, dport=dport)
    return stamp(eth() / r / DNS(qr=1, rcode=rcode, qd=DNSQR(qname=qname)), ts)
