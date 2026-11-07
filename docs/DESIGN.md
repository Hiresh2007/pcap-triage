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
