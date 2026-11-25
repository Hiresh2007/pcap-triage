import base64
import json

from scapy.layers.inet import IP, TCP

from pcap_triage.detectors import detect_cleartext_credentials
from pcap_triage.reader import read_packets

from .conftest import T0, eth, stamp, tcp

CLIENT, SERVER = "192.0.2.20", "198.51.100.80"
SECRET = b"hunter2-Secret!"


def data(payload: bytes, dport: int, ts: float = T0, sport: int = 51000):
    pkt = IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=dport, flags="PA") / payload
    return stamp(eth() / pkt, ts)


def run(write_pcap, packets):
    records, _ = read_packets(write_pcap(packets))
    return detect_cleartext_credentials(records)


def assert_no_secret(findings):
    dumped = json.dumps([f.to_dict() for f in findings])
    assert SECRET.decode() not in dumped


def test_http_basic(write_pcap):
    auth = base64.b64encode(b"alice:" + SECRET).decode()
    req = f"GET /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {auth}\r\n\r\n".encode()
    (f,) = run(write_pcap, [data(req, 8080)])
    assert f.title == "Cleartext HTTP Basic credentials"
    assert f.evidence["usernames"] == ["alice"]
    assert f.evidence["password_lengths"] == [len(SECRET)]
    assert f.attack_technique == "T1040"
    assert_no_secret([f])


def test_ftp_user_pass(write_pcap):
    pkts = [data(b"USER bob\r\n", 21), data(b"PASS " + SECRET + b"\r\n", 21, T0 + 1)]
    (f,) = run(write_pcap, pkts)
    assert (f.evidence["protocol"], f.evidence["usernames"]) == ("FTP", ["bob"])
    assert f.evidence["passwords_observed"] == 1
    assert_no_secret([f])


def test_pop3_and_imap(write_pcap):
    pkts = [
        data(b"USER carol\r\n", 110),
        data(b"PASS " + SECRET + b"\r\n", 110, T0 + 1),
        data(b'a001 LOGIN dave "' + SECRET + b'"\r\n', 143, T0 + 2, sport=51001),
    ]
    found = {f.evidence["protocol"]: f for f in run(write_pcap, pkts)}
    assert found["POP3"].evidence["usernames"] == ["carol"]
    assert found["IMAP"].evidence["usernames"] == ["dave"]
    assert found["IMAP"].evidence["password_lengths"] == [len(SECRET)]
    assert_no_secret(found.values())


def test_telnet_session(write_pcap):
    (f,) = run(write_pcap, [data(b"root\r\n", 23)])
    assert f.title == "Cleartext Telnet session"


def test_scan_probe_to_port_23_is_not_a_telnet_session(write_pcap):
    assert run(write_pcap, [tcp(CLIENT, SERVER, 51000, 23, "S", T0)]) == []


def test_encrypted_and_unauthenticated_traffic_not_flagged(write_pcap):
    pkts = [
        data(bytes(range(256)), 443),  # TLS-like bytes
        data(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", 80),
        data(b"GET / HTTP/1.1\r\nAuthorization: Bearer abc.def\r\n\r\n", 80),
        data(b"USER eve\r\n", 2121),  # FTP command on a non-FTP port: not parsed
    ]
    assert run(write_pcap, pkts) == []


def test_invalid_basic_header_ignored(write_pcap):
    assert run(write_pcap, [data(b"GET / HTTP/1.1\r\nAuthorization: Basic ###\r\n\r\n", 80)]) == []


def test_username_control_bytes_escaped(write_pcap):
    (f,) = run(write_pcap, [data(b"USER ev\x1bil\r\n", 21)])
    assert f.evidence["usernames"] == [r"ev\x1bil"]
