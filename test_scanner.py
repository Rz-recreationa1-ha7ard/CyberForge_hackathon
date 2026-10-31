"""
Unit tests for scanner.py (Nmap service/version parsing, ScopeGate verification, and State recording).
"""

import os
from pathlib import Path
import tempfile
import unittest

from scanner import is_risky_service, parse_nmap_text, record_scan_results, scan_host
from scope import ScopeGate
import state

SAMPLE_NMAP_OUTPUT = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-31 08:30 UTC
Nmap scan report for 10.10.10.50
Host is up (0.0018s latency).
Not shown: 994 closed tcp ports (reset), 1 filtered port
PORT     STATE    SERVICE      VERSION
21/tcp   open     ftp          vsftpd 3.0.3
22/tcp   open     ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
23/tcp   open     telnet       Linux telnetd
80/tcp   open     http         Apache httpd 2.4.41 ((Ubuntu))
445/tcp  open     microsoft-ds Samba smbd 4.6.2
3306/tcp closed   mysql        MySQL 5.7.35
8080/tcp filtered http-proxy

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
"""


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_scanner.db")
        state.init_db(self.db_path)

        self.scope_config = {
            "network_ranges": ["10.10.10.0/24"],
            "excluded": ["10.10.10.1"],
            "binaries": ["nmap", "/usr/bin/nmap", "nmap.exe"],
        }
        self.gate = ScopeGate(config_dict=self.scope_config)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_nmap_text(self):
        """Verify only 'open' ports are extracted with service, version, and protocol."""
        ports = parse_nmap_text(SAMPLE_NMAP_OUTPUT)
        self.assertEqual(len(ports), 5)  # 21, 22, 23, 80, 445 (3306 closed and 8080 filtered excluded)

        ports_by_num = {p["port"]: p for p in ports}

        # FTP
        self.assertIn(21, ports_by_num)
        self.assertEqual(ports_by_num[21]["service"], "ftp")
        self.assertEqual(ports_by_num[21]["version"], "vsftpd 3.0.3")
        self.assertEqual(ports_by_num[21]["protocol"], "tcp")

        # Telnet
        self.assertIn(23, ports_by_num)
        self.assertEqual(ports_by_num[23]["service"], "telnet")
        self.assertEqual(ports_by_num[23]["version"], "Linux telnetd")

        # HTTP
        self.assertIn(80, ports_by_num)
        self.assertEqual(ports_by_num[80]["service"], "http")
        self.assertIn("Apache", ports_by_num[80]["version"])

        # SMB
        self.assertIn(445, ports_by_num)
        self.assertEqual(ports_by_num[445]["service"], "microsoft-ds")

    def test_is_risky_service(self):
        """Verify detection of inherently risky unauthenticated services."""
        self.assertIsNotNone(is_risky_service("ftp"))
        self.assertIsNotNone(is_risky_service("telnet"))
        self.assertIsNotNone(is_risky_service("smb"))
        self.assertIsNotNone(is_risky_service("microsoft-ds"))
        self.assertIsNotNone(is_risky_service("netbios-ssn"))
        self.assertIsNotNone(is_risky_service("rlogin"))

        # Safe / standard encrypted services
        self.assertIsNone(is_risky_service("ssh"))
        self.assertIsNone(is_risky_service("https"))
        self.assertIsNone(is_risky_service("http"))

    def test_record_scan_results_state_and_findings(self):
        """Verify state updates: host open_ports, tested_surfaces ('network'), and categorized findings."""
        ip = "10.10.10.50"
        ports = parse_nmap_text(SAMPLE_NMAP_OUTPUT)

        results = record_scan_results(ip, ports, db_path=self.db_path)
        self.assertTrue(results["success"])
        self.assertEqual(len(results["finding_ids"]), 5)

        # 1. Verify Host record in SQLite
        host = state.get_host(ip, db_path=self.db_path)
        self.assertIsNotNone(host)
        self.assertIn("network", host["tested_surfaces"])
        self.assertEqual(len(host["open_ports"]), 5)

        # 2. Verify Findings in SQLite
        findings = state.list_findings(host_id=ip, db_path=self.db_path)
        self.assertEqual(len(findings), 5)

        findings_by_port = {int(f["surface"].split("/")[1].split("-")[0]): f for f in findings}

        # FTP (port 21): must be 'Vulnerability Analysis' with explanatory description
        ftp_finding = findings_by_port[21]
        self.assertEqual(ftp_finding["ptes_phase"], "Vulnerability Analysis")
        self.assertEqual(ftp_finding["verified"], "unverified")
        self.assertIn("cleartext", ftp_finding["description"].lower())

        # Telnet (port 23): must be 'Vulnerability Analysis'
        telnet_finding = findings_by_port[23]
        self.assertEqual(telnet_finding["ptes_phase"], "Vulnerability Analysis")
        self.assertEqual(telnet_finding["severity"], "high")

        # SMB (port 445): must be 'Vulnerability Analysis'
        smb_finding = findings_by_port[445]
        self.assertEqual(smb_finding["ptes_phase"], "Vulnerability Analysis")

        # SSH (port 22) & HTTP (port 80): must be 'Intelligence Gathering'
        ssh_finding = findings_by_port[22]
        self.assertEqual(ssh_finding["ptes_phase"], "Intelligence Gathering")
        self.assertEqual(ssh_finding["severity"], "info")

        http_finding = findings_by_port[80]
        self.assertEqual(http_finding["ptes_phase"], "Intelligence Gathering")
        self.assertEqual(http_finding["severity"], "info")

    def test_scan_host_in_scope_with_mock_runner(self):
        """Verify scan_host executes with correct flags and records state when in scope."""
        captured_cmd = []

        def mock_runner(cmd, timeout):
            nonlocal captured_cmd
            captured_cmd = cmd
            return SAMPLE_NMAP_OUTPUT

        ip = "10.10.10.50"
        res = scan_host(
            ip,
            gate=self.gate,
            nmap_bin="nmap",
            timeout_seconds=120,
            max_retries=2,
            db_path=self.db_path,
            runner=mock_runner,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["open_ports_count"], 5)

        # Verify command flags
        self.assertIn("-sV", captured_cmd)
        self.assertIn("--max-retries", captured_cmd)
        self.assertIn("2", captured_cmd)
        self.assertIn("--host-timeout", captured_cmd)
        self.assertIn("120s", captured_cmd)
        self.assertIn(ip, captured_cmd)

    def test_scan_host_blocked_by_scope_gate(self):
        """Verify ScopeGate blocks out-of-scope and excluded targets before scan runs."""
        runner_called = False

        def mock_runner(cmd, timeout):
            nonlocal runner_called
            runner_called = True
            return ""

        # 1. Excluded IP (10.10.10.1)
        res_ex = scan_host("10.10.10.1", gate=self.gate, runner=mock_runner)
        self.assertFalse(res_ex["success"])
        self.assertFalse(runner_called)
        self.assertIn("excluded", res_ex["error"].lower())

        # 2. Out-of-scope IP (8.8.8.8)
        res_out = scan_host("8.8.8.8", gate=self.gate, runner=mock_runner)
        self.assertFalse(res_out["success"])
        self.assertFalse(runner_called)
        self.assertIn("out of authorized scope", res_out["error"].lower())

        # Verify violations logged in gate
        self.assertEqual(len(self.gate.violations), 2)


if __name__ == "__main__":
    unittest.main()
