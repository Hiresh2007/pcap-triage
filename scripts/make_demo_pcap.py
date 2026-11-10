"""Generate a synthetic lab capture for demos: benign web/DNS traffic plus a SYN scan,
an SMB sweep, DNS tunnelling and DGA-style NXDOMAIN bursts.
Uses RFC 5737 documentation addresses only.

    python scripts/make_demo_pcap.py samples/demo_scan.pcap
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

T0 = 1_700_000_000.0
SCANNER, VICTIM, CLIENT, DNS_SRV = "192.0.2.66", "198.51.100.10", "192.0.2.20", "192.0.2.53"
TUNNEL_CLIENT, DGA_HOST = "192.0.2.31", "192.0.2.47"
OPEN_PORTS = {22, 80, 443}


def pkt(layers, ts):
    p = Ether(src="02:00:00:00:00:0a", dst="02:00:00:00:00:0b") / layers
    p.time = ts
    return p


def build(seed: int = 7) -> list:
    rng = random.Random(seed)  # noqa: S311 - deterministic demo data, not security use
    out = []
    # benign: a client resolving a name and making HTTPS requests
    for i in range(5):
        ts = T0 + i * 2
        q = IP(src=CLIENT, dst=DNS_SRV) / UDP(sport=50000 + i, dport=53)
        out.append(pkt(q / DNS(rd=1, qd=DNSQR(qname="intranet.example")), ts))
        sport = 51000 + i
        for flags, a, b in (("S", CLIENT, VICTIM), ("SA", VICTIM, CLIENT), ("A", CLIENT, VICTIM)):
            sp, dp = (sport, 443) if a == CLIENT else (443, sport)
            out.append(pkt(IP(src=a, dst=b) / TCP(sport=sp, dport=dp, flags=flags), ts + 0.1))
    # vertical SYN scan of ports 1-100 plus 443 and 8080, in randomised order (like nmap)
    ports = [*range(1, 101), 443, 8080]
    rng.shuffle(ports)
    for i, port in enumerate(ports):
        ts = T0 + 15 + i * 0.005
        out.append(pkt(IP(src=SCANNER, dst=VICTIM) / TCP(sport=61000, dport=port, flags="S"), ts))
        reply = "SA" if port in OPEN_PORTS else "RA"
        out.append(
            pkt(IP(src=VICTIM, dst=SCANNER) / TCP(sport=port, dport=61000, flags=reply), ts + 0.001)
        )
    # horizontal sweep for SMB across a /27
    for i in range(1, 31):
        ts = T0 + 20 + i * 0.02
        out.append(
            pkt(
                IP(src=SCANNER, dst=f"198.51.100.{i + 100}")
                / TCP(sport=61001, dport=445, flags="S"),
                ts,
            )
        )
    # DNS tunnelling: a second client exfiltrates text as hex labels via TXT queries
    data = ("lab exfil test: contents of /etc/hostname and a fake api key 0000 " * 8).encode()
    for i in range(0, len(data), 16):
        name = f"{i // 16:02x}{data[i : i + 16].hex()}.t.example.net"
        q = IP(src=TUNNEL_CLIENT, dst=DNS_SRV) / UDP(sport=53530, dport=53)
        out.append(pkt(q / DNS(rd=1, qd=DNSQR(qname=name, qtype="TXT")), T0 + 25 + i / 64))
    # DGA-like behaviour: a third host gets NXDOMAIN for many generated names
    for i in range(25):
        label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(14))
        name, ts = f"{label}.com", T0 + 30 + i * 0.3
        q = IP(src=DGA_HOST, dst=DNS_SRV) / UDP(sport=53531, dport=53)
        r = IP(src=DNS_SRV, dst=DGA_HOST) / UDP(sport=53, dport=53531)
        out.append(pkt(q / DNS(rd=1, qd=DNSQR(qname=name)), ts))
        out.append(pkt(r / DNS(qr=1, rcode=3, qd=DNSQR(qname=name)), ts + 0.02))
    return sorted(out, key=lambda p: p.time)


if __name__ == "__main__":
    dest = Path(sys.argv[1] if len(sys.argv) > 1 else "samples/demo_scan.pcap")
    dest.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(dest), build())
    print(f"wrote {dest}")
