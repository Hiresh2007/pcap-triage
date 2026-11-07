# Design notes

## Data flow

```
pcap/pcapng ──► reader.iter_packets ──► PacketRecord[] ──┬──► flows.summarize ──► CaptureSummary
                (Scapy PcapReader,                        │
                 streaming)                               └──► detectors.* ──────► Finding[]
                                                                                     │
                                         report.render_text / render_json ◄──────────┘
```

* **`PacketRecord`** is a frozen dataclass with only the fields detectors need
  (timestamp, addresses, protocol, ports, TCP flags, length). Scapy packet
  objects are large; converting once keeps later passes cheap and lets
  detectors be unit-tested without Scapy at all.
* **Flows are directional** (`A:p -> B:q` and `B:q -> A:p` are separate). That
  is simpler to reason about for "who initiated" questions. Bidirectional
  session pairing can be layered on top later.
* **DNS fields** (first question name, type, query/response flag, rcode) are
  attached to UDP/53 records as `DnsInfo`. Malformed payloads on port 53 give
  `dns=None` instead of an exception.
* **Detectors are pure functions** `records -> list[Finding]`. Each finding has
  a JSON-serialisable `evidence` dict so the reasoning behind an alert can be
  checked by hand.

## Port-scan detection

### Signal

An initial TCP connection attempt is a packet with **SYN set and ACK clear**.
SYN-ACK and RST packets are replies, not probes, and are used only to work out
which probed ports were open or closed.

* Vertical scan: group SYNs by `(source, target)` and count distinct
  destination ports.
* Horizontal sweep: group SYNs by `(source, destination port)` and count
  distinct targets.

### Sliding window

Counting distinct ports over the whole capture would flag a host that opens a
handful of connections per hour for days. Instead,
`max_distinct_in_window` finds the window of `--scan-window` seconds holding
the most distinct values using a two-pointer sweep over time-sorted events:

1. Advance the right pointer, adding its value to a counter.
2. While the oldest event is more than `window` seconds older than the newest,
   drop it from the counter (removing the key when its count reaches zero).
3. `len(counter)` is the number of distinct values in the current window.

Retransmitted SYNs to the same port only increase a count, never the number of
distinct keys. Cost: O(n log n) for the sort, O(n) for the sweep.

### Defaults and their rationale

| Setting | Default | Reason |
|---|---|---|
| ports per host | 15 | Normal clients rarely touch more than a few service ports on one server within a minute |
| hosts per port | 10 | Catches subnet sweeps for common services (22, 445, 3389) |
| window | 60 s | Covers default Nmap timing (T3) with margin |

### Limitations / evasion

* **Slow scans** (e.g. Nmap `-T0/-T1`, one probe every few minutes) fall
  outside the window. Raising `--scan-window` catches them at the cost of more
  false positives. This is tested explicitly.
* **Distributed scans** from many sources are not correlated.
* **NULL/FIN/Xmas scans and UDP scans** do not send SYN and are not detected
  yet.
* **False positives:** NAT gateways and proxies (many users behind one IP),
  authorised vulnerability scanners, passive FTP and MS-RPC dynamic ports.

## DNS anomaly detection

### Tunnelling (`dns.tunnel`, T1071.004)

Tunnelling tools (iodine, dnscat2, custom exfiltration scripts) encode data
into subdomain labels of a domain the attacker controls, so the resolver
forwards every query to the attacker's authoritative server.

For every `(client, registered domain)` pair, over all queries in the capture:

| Signal | Default | Why |
|---|---|---|
| unique subdomains | ≥ 15 | Each chunk of data produces a new name; caching makes normal names repeat |
| mean subdomain length | ≥ 20 chars | Encoded chunks are long; normal hostnames (`www`, `mail`, `api`) are short |
| mean Shannon entropy | ≥ 3.0 bits/char | Encoded data uses its alphabet evenly |

All three must hold. Entropy alone is weak on short strings (a 4-character
string can have at most 2 bits/char), which is why length is a separate
condition.

**Why 3.0 and not 3.5.** The first version used 3.5. Testing against hex
encoding of *ordinary text* showed a mean of about 3.2–3.35 bits/char: hex
has a 16-symbol alphabet (maximum 4.0), and text only produces some nibble
pairs. Uniformly random hex (e.g. encrypted payloads) reaches about 3.9. A
3.5 threshold would have missed plain-text exfiltration encoded as hex;
`test_detects_hex_encoded_text_tunnel` locks this in.

The **registered domain** is approximated as the last two labels, or three
for a short list of two-label public suffixes (`co.uk`, `com.au`, ...). A full
Public Suffix List would be more accurate; it is a candidate dependency.

### NXDOMAIN rate (`dns.nxdomain`, T1568.002)

DGA malware generates many candidate C2 domains and tries them until one
resolves, so most of its lookups fail. Per client (the destination of DNS
replies): at least 10 distinct names answered NXDOMAIN **and** NXDOMAIN being
at least 50 % of all replies. The ratio condition stops a busy, otherwise
healthy client from being flagged for a handful of typos.

### Limitations and false positives

* Aggregation is over the whole capture, not a sliding window: tunnelling is
  usually sustained, but a long capture of a busy resolver can accumulate
  counts. Windowing like the scan detector is a possible refinement.
* Only UDP/53 is parsed. DNS over TCP, DoT (853) and DoH (443) are not visible.
* NXDOMAIN detection needs the resolver's replies in the capture. Tunnelling is
  detected from queries alone and grouped by domain rather than resolver, so it
  also works when a client uses a non-standard resolver.
* Query names are attacker-controlled bytes. The reader escapes anything outside
  printable ASCII as `\xNN`, so reports cannot carry terminal escape sequences.
* False positives: AV/reputation lookups and DNSBLs that encode data into
  names, some telemetry and CDN schemes, and misconfigured DNS search suffixes
  (NXDOMAIN bursts).
