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
* NULL / FIN / Xmas and UDP scans are covered separately (below).
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

## Beaconing detection (`beacon`, T1071)

Implants contact their C2 server on a timer, usually with random jitter to
look less mechanical. The detector measures how *regular* contact is between
one source and one destination service; volume is irrelevant.

### Method

Per channel `(src, dst, dst port, protocol)`:

1. **Events.** TCP: each new connection (SYN without ACK), which identifies
   the initiator exactly. UDP: each datagram towards the lower-numbered port,
   assumed to be the service (clients normally use high ephemeral ports).
   Events less than 2 s apart are merged into one check-in.
2. **Intervals** between consecutive check-ins.
3. **Typical interval** = median. **Jitter** = median absolute deviation (MAD)
   divided by the median.
4. Flag when there are ≥ 8 check-ins, the median interval is ≥ 5 s, and
   jitter ≤ 0.2.

Median and MAD are used instead of mean and standard deviation because they
are robust: a single lost or delayed check-in doubles one interval, which
would inflate a standard deviation but leaves the median and MAD almost
unchanged (`test_one_missed_beacon_barely_moves_robust_stats`).

### Measured behaviour of the 0.2 threshold

Simulated with 200 trials per row (uniform jitter around a 60 s interval;
"irregular" = exponential gaps with mean 60 s plus 5 s):

| Traffic | Flagged |
|---|---|
| beacon, ±10 % jitter, 12 check-ins | 100 % |
| beacon, ±20 % jitter | 100 % |
| beacon, ±30 % jitter | 96 % |
| beacon, ±40 % jitter | 70 % |
| beacon, ±50 % jitter | 45 % |
| irregular, 8 events | 2.5 % |
| irregular, 12 events | 1.0 % |
| irregular, 30 events | 0 % |

Heavy jitter (≥ 40 %) is a deliberate evasion and partly succeeds. False
positives on irregular traffic fall as the number of events grows, which is
why `--beacon-min-events` matters more than the jitter threshold for
precision.

### Limitations and false positives

* Beacons that keep one long-lived TCP connection open send a single SYN and
  are invisible to this method; per-connection payload timing would be needed.
* UDP services on a port higher than the client's are mis-oriented.
* Legitimate periodic traffic: NTP and DNS (ignored by default), monitoring
  agents, health checks, update polling, push-notification keep-alives. These
  need allow-lists (roadmap: per-detector allow-lists).
* Very slow beacons (hours) need captures long enough to contain ≥ 8 check-ins.

## Allow-lists

Every detector has known benign sources (scanners you run, agents that
beacon by design, reputation services that encode data in DNS). Allow-lists
are applied **after** detection as a filter over findings:

* A rule matches when all of its fields match (`detector` glob, `src`/`dst`
  IP or CIDR, evidence `port`, evidence `domain` including subdomains). A rule
  must set at least one condition, and `reason` is mandatory.
* Unknown fields are an error. A typo such as `prot = 443` would otherwise
  leave a rule with no effective condition, which would suppress everything.
* Suppressed findings are **kept and reported** with their reason, in text
  and JSON, so an allow-list can be reviewed. Silent suppression is how real
  intrusions get hidden behind stale exceptions.
* `--fail-on-findings` considers only unsuppressed findings.

Filtering findings, rather than excluding traffic before detection, keeps
detector statistics unchanged and makes every suppression traceable to a
rule.

## Stealth TCP and UDP scans

Same sliding window and `--scan-ports` threshold as the SYN vertical scan,
counted per probe type and `(scanner, target)`.

| Detector | Probe | Closed port answers | Open / filtered |
|---|---|---|---|
| `portscan.null` | TCP, no flags | RST | silent |
| `portscan.fin` | TCP, FIN only | RST | silent |
| `portscan.xmas` | TCP, FIN+PSH+URG | RST | silent |
| `portscan.udp` | UDP datagram | ICMP type 3 code 3 (port unreachable) | silent or a UDP reply |

* These TCP flag combinations never occur in a normal conversation (FIN is
  always sent with ACK on a real connection), which is why Nmap's `-sN/-sF/-sX`
  are detectable at all. FIN+ACK teardowns are explicitly not counted.
* "Open or filtered" is reported rather than "open" because silence is the
  answer for both: the probe type cannot tell them apart.
* The reader records the destination port quoted inside ICMP errors, which is
  how a port-unreachable message is tied back to the probed port.
* UDP probes are counted only towards the lower-numbered port. Without that,
  a DNS server answering one client on many ephemeral ports would look like a
  UDP scan of the client (`test_dns_replies_to_many_client_ports_not_a_udp_scan`).
  A scan sent *from* a low source port (e.g. `--source-port 53`) is missed by
  this rule; it is a known evasion.

## Cleartext credentials (`cleartext.credentials`, T1040 context)

The reader keeps the first 256 bytes of each TCP payload, enough to see a
login command without holding full streams in memory.

| Protocol | Signal |
|---|---|
| HTTP Basic | `Authorization: Basic <base64>` header on any port, decoded to `user:password` |
| FTP / POP3 | `USER` / `PASS` commands to ports 21 / 110 |
| IMAP | `<tag> LOGIN <user> <password>` to port 143 |
| Telnet | client data to port 23 (a bare SYN from a scan does not count) |

* **Secrets are never stored or reported.** Evidence holds usernames and
  password lengths only, and a test checks the JSON output for the password.
* Usernames are attacker-controllable bytes and are escaped like DNS names.
* Limits: commands split across TCP segments, non-standard ports for FTP /
  POP3 / IMAP, and STARTTLS upgrades (credentials after the upgrade are
  encrypted, correctly not flagged) are not reassembled or tracked.
