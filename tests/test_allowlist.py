import json

import pytest

from pcap_triage.allowlist import AllowlistError, apply_allowlist, load_allowlist, parse_rules
from pcap_triage.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from pcap_triage.detectors import Finding, Severity

from .test_beacon import beacon_times, tcp_checkins


def finding(detector="beacon", src="192.0.2.88", dst="203.0.113.50", **evidence):
    return Finding(detector, "t", Severity.MEDIUM, src, dst, 0.0, 1.0, "d", evidence=evidence)


def rules(*entries):
    return parse_rules({"allow": list(entries)})


@pytest.mark.parametrize(
    ("rule", "matched"),
    [
        ({"detector": "beacon"}, True),
        ({"detector": "dns.*"}, False),
        ({"src": "192.0.2.0/24"}, True),
        ({"src": "198.51.100.0/24"}, False),
        ({"dst": "203.0.113.50"}, True),
        ({"port": 443}, True),
        ({"port": 80}, False),
        ({"detector": "beacon", "src": "192.0.2.88", "port": 80}, False),  # all must match
    ],
)
def test_rule_matching(rule, matched):
    kept, suppressed = apply_allowlist([finding(port=443)], rules({**rule, "reason": "r"}))
    assert (len(suppressed) == 1) is matched
    assert len(kept) + len(suppressed) == 1


def test_domain_matches_subdomains_but_not_lookalikes():
    r = rules({"domain": "example.net", "reason": "r"})
    assert apply_allowlist([finding("dns.tunnel", domain="t.example.net")], r)[1]
    assert not apply_allowlist([finding("dns.tunnel", domain="badexample.net")], r)[1]


def test_dst_rule_never_matches_finding_without_dst():
    kept, _ = apply_allowlist(
        [finding("portscan.horizontal", dst=None)], rules({"dst": "0.0.0.0/0", "reason": "r"})
    )
    assert len(kept) == 1


def test_first_matching_rule_gives_reason():
    r = rules({"port": 443, "reason": "first"}, {"detector": "beacon", "reason": "second"})
    (s,) = apply_allowlist([finding(port=443)], r)[1]
    assert s.reason == "first"


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"detector": "beacon"}, "'reason' is required"),
        ({"reason": "only a reason"}, "at least one condition"),
        ({"src": "not-an-ip", "reason": "r"}, "invalid IP"),
        ({"port": 70000, "reason": "r"}, "port must be"),
        ({"prot": 443, "reason": "r"}, "unknown field"),  # typo must not silently match all
    ],
)
def test_invalid_rules_rejected(entry, message):
    with pytest.raises(AllowlistError, match=message):
        rules(entry)


def test_load_errors(tmp_path):
    with pytest.raises(AllowlistError, match="cannot read"):
        load_allowlist(tmp_path / "missing.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("[[allow]\n")
    with pytest.raises(AllowlistError, match="invalid TOML"):
        load_allowlist(bad)


def test_cli_suppresses_and_reports(write_pcap, tmp_path, capsys):
    pcap = write_pcap(tcp_checkins(beacon_times(12, 60)))
    allow = tmp_path / "allow.toml"
    allow.write_text('[[allow]]\ndetector = "beacon"\nport = 443\nreason = "EDR heartbeat"\n')

    assert main(["analyze", str(pcap), "--fail-on-findings"]) == EXIT_FINDINGS
    capsys.readouterr()
    assert main(["analyze", str(pcap), "--allowlist", str(allow), "--fail-on-findings"]) == EXIT_OK
    out = capsys.readouterr().out
    assert (
        "Findings (0)" in out and "Suppressed by allow-list (1)" in out and "EDR heartbeat" in out
    )

    main(["analyze", str(pcap), "--allowlist", str(allow), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["findings"] == []
    assert data["suppressed"][0]["reason"] == "EDR heartbeat"


def test_cli_rejects_invalid_allowlist(write_pcap, tmp_path, capsys):
    pcap = write_pcap(tcp_checkins(beacon_times(12, 60)))
    allow = tmp_path / "allow.toml"
    allow.write_text('[[allow]]\ndetector = "beacon"\n')
    assert main(["analyze", str(pcap), "--allowlist", str(allow)]) == EXIT_ERROR
    assert "'reason' is required" in capsys.readouterr().err
