import json

from pcap_triage.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

from .conftest import handshake, vertical_scan

BENIGN = handshake("192.0.2.5", "198.51.100.10", 50000, 443, 1_700_000_000.0)


def test_text_report(write_pcap, capsys):
    path = write_pcap(vertical_scan(range(1, 30), open_ports={22}))
    assert main(["analyze", str(path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "TCP vertical port scan [T1046]" in out
    assert "open ports: 22" in out


def test_json_report_structure(write_pcap, capsys):
    path = write_pcap(BENIGN)
    assert main(["analyze", str(path), "--format", "json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["capture"]["ip_packets"] == 3
    assert data["capture"]["flow_count"] == 2
    assert data["findings"] == []
    assert data["capture"]["first_seen"].endswith("+00:00")


def test_fail_on_findings_exit_code(write_pcap, capsys):
    scan = write_pcap(vertical_scan(range(1, 30)), "scan.pcap")
    clean = write_pcap(BENIGN, "clean.pcap")
    assert main(["analyze", str(scan), "--fail-on-findings"]) == EXIT_FINDINGS
    assert main(["analyze", str(clean), "--fail-on-findings"]) == EXIT_OK


def test_threshold_flags_change_result(write_pcap, capsys):
    path = write_pcap(vertical_scan(range(1, 30)))
    main(["analyze", str(path), "--format", "json", "--scan-ports", "50"])
    assert json.loads(capsys.readouterr().out)["findings"] == []


def test_missing_file(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "nope.pcap")]) == EXIT_ERROR
    assert "no such file" in capsys.readouterr().err


def test_invalid_threshold(write_pcap, capsys):
    path = write_pcap(BENIGN)
    assert main(["analyze", str(path), "--scan-window", "0"]) == EXIT_ERROR
    assert "window_seconds" in capsys.readouterr().err


def test_not_a_pcap(tmp_path, capsys):
    bogus = tmp_path / "notes.pcap"
    bogus.write_text("this is not a packet capture")
    assert main(["analyze", str(bogus)]) == EXIT_ERROR
    assert "could not read" in capsys.readouterr().err


def test_dns_findings_in_text_report(write_pcap, capsys):
    from .test_dns import dga_traffic, tunnel_traffic

    path = write_pcap(tunnel_traffic() + dga_traffic(), "dns.pcap")
    assert main(["analyze", str(path), "--fail-on-findings"]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "Possible DNS tunnelling via example.net [T1071.004]" in out
    assert "High NXDOMAIN rate (possible DGA) [T1568.002]" in out
    assert "e.g. " in out


def test_dns_threshold_flags(write_pcap, capsys):
    from .test_dns import tunnel_traffic

    path = write_pcap(tunnel_traffic(), "dns.pcap")
    main(["analyze", str(path), "--format", "json", "--dns-min-subdomains", "100"])
    assert json.loads(capsys.readouterr().out)["findings"] == []
    assert main(["analyze", str(path), "--dns-min-nxdomain", "1"]) == EXIT_ERROR
