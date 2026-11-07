# pcap-triage

Offline triage for packet captures. `pcap-triage` reads a `.pcap` / `.pcapng`
file, summarises who talked to whom, and runs a set of small, explainable
detectors whose output an analyst can verify by hand in Wireshark.

It is meant for the first ten minutes with an unfamiliar capture, such as a lab
exercise, a CTF challenge or a capture exported from a sensor, before reaching
for heavier tools like Zeek or Suricata.

> Status: early development (v0.1). Port-scan detection is implemented and
> tested; further detectors are on the [roadmap](#roadmap).

## Features

| Area | What it does |
|---|---|
| Reader | Streams pcap and pcapng via Scapy; IPv4 and IPv6; TCP, UDP, ICMP |
| Flow summary | Directional 5-tuple flows, protocol mix, top talkers, top flows by bytes |
| `portscan.vertical` | One source SYN-probing many ports on one host within a sliding window. Reports which probed ports answered SYN-ACK (open) |
| `portscan.horizontal` | One source SYN-probing one port across many hosts (e.g. SMB/445 sweeps) |
| Output | Text report for humans, JSON for pipelines; `--fail-on-findings` exit code for scripting |

Each finding has a MITRE ATT&CK technique ID where one applies
(port scans map to [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/)).

## Install

```bash
git clone https://github.com/Hiresh2007/pcap-triage.git
cd pcap-triage
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Reading capture files does not need libpcap/Npcap. Scapy may print
`No libpcap provider available`, which is harmless for offline analysis.

## Usage

```bash
python scripts/make_demo_pcap.py samples/demo_scan.pcap   # synthetic lab capture
pcap-triage analyze samples/demo_scan.pcap
```

```text
Findings (2)
  [MEDIUM] TCP vertical port scan [T1046]
      192.0.2.66 sent SYNs to 102 distinct ports on 198.51.100.10 within 0.5s (threshold 15 in 60s).
      open ports: 22, 80, 443
  [MEDIUM] TCP horizontal sweep on port 445 [T1046]
      192.0.2.66 sent SYNs to port 445 on 30 distinct hosts within 0.6s (threshold 10 in 60s).
```

Options:

```text
--format {text,json}   output format (default text)
--top N                rows in top-N tables
--scan-ports N         distinct ports on one host that count as a vertical scan (default 15)
--scan-hosts N         distinct hosts on one port that count as a horizontal sweep (default 10)
--scan-window SECONDS  sliding window for scan detection (default 60)
--fail-on-findings     exit 1 when any finding is produced
```

Exit codes: `0` success, `1` findings present (only with `--fail-on-findings`), `2` input error.

## How detection works

See [docs/DESIGN.md](docs/DESIGN.md) for the data flow and the reasoning
behind each detector, including known false positives and evasion.

## Development

```bash
pytest          # unit + CLI tests, using synthetic captures built with Scapy
ruff check .    # lint (includes flake8-bandit security rules)
ruff format .
```

Test fixtures use RFC 5737 documentation addresses (192.0.2.0/24,
198.51.100.0/24) and are generated at test time; no real traffic is committed.

## Roadmap

- [x] Streaming reader, flow summary, text/JSON reports
- [x] Vertical and horizontal TCP SYN scan detection
- [ ] DNS anomalies: long / high-entropy query names (tunnelling, DGA)
- [ ] Beaconing: regular-interval connections (C2 heartbeat)
- [ ] ARP spoofing: IP-to-MAC binding changes
- [ ] Cleartext credentials: HTTP Basic, FTP, Telnet
- [ ] UDP scan detection; detector allow-lists
- [ ] Validation against public lab captures and Nmap traffic recorded in a local VM

## Responsible use

Analyse only traffic you are authorised to inspect: your own lab, CTF
material or captures you have permission to handle. Captures can contain
credentials and personal data; do not commit them to public repositories.

## License

MIT, see [LICENSE](LICENSE).
