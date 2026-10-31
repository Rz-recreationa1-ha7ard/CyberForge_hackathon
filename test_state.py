"""
Unit and concurrency tests for state.py
"""

from concurrent.futures import ThreadPoolExecutor
import os
import sqlite3
import tempfile
import unittest

import state


class TestStateCoordination(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_state.db")
        state.init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_schema_created(self):
        """Verify tables and columns match the CTF specifications."""
        with state.get_connection(self.db_path) as conn:
            # Check tables exist
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
            self.assertIn("hosts", tables)
            self.assertIn("findings", tables)
            self.assertIn("attack_path", tables)

            # Check hosts columns
            host_cols = {r["name"]: r for r in conn.execute("PRAGMA table_info(hosts);").fetchall()}
            for col in ["id", "ip", "status", "claimed_by", "tested_surfaces", "open_ports", "first_seen", "last_updated"]:
                self.assertIn(col, host_cols)
            self.assertEqual(host_cols["id"]["pk"], 1)

            # Check findings columns
            finding_cols = {r["name"]: r for r in conn.execute("PRAGMA table_info(findings);").fetchall()}
            for col in ["id", "host_id", "surface", "type", "ptes_phase", "description", "evidence", "verified", "severity", "timestamp"]:
                self.assertIn(col, finding_cols)
            self.assertEqual(finding_cols["id"]["pk"], 1)

            # Check attack_path columns
            ap_cols = {r["name"]: r for r in conn.execute("PRAGMA table_info(attack_path);").fetchall()}
            for col in ["step", "finding_id", "leads_to_finding_id", "notes"]:
                self.assertIn(col, ap_cols)

    def test_add_and_get_host_defaults(self):
        """Verify host insertion defaults (status='discovered', empty JSON arrays)."""
        ip = "10.10.11.1"
        hid = state.add_host(ip, db_path=self.db_path)
        self.assertEqual(hid, ip)

        host = state.get_host(ip, db_path=self.db_path)
        self.assertIsNotNone(host)
        self.assertEqual(host["id"], ip)
        self.assertEqual(host["ip"], ip)
        self.assertEqual(host["status"], "discovered")
        self.assertIsNone(host["claimed_by"])
        self.assertEqual(host["tested_surfaces"], [])
        self.assertEqual(host["open_ports"], [])
        self.assertIsNotNone(host["first_seen"])
        self.assertIsNotNone(host["last_updated"])

    def test_add_host_with_ports_and_surfaces(self):
        """Verify open_ports structured as JSON array of objects with port/service/version."""
        ip = "192.168.1.50"
        ports = [
            {"port": 80, "service": "http", "version": "Apache httpd 2.4.41"},
            {"port": 22, "service": "ssh", "version": "OpenSSH 8.2p1"}
        ]
        surfaces = ["initial-scan"]
        state.add_host(ip, open_ports=ports, tested_surfaces=surfaces, db_path=self.db_path)

        host = state.get_host(ip, db_path=self.db_path)
        self.assertEqual(host["open_ports"], ports)
        self.assertEqual(host["tested_surfaces"], surfaces)

    def test_claim_host_atomic_race(self):
        """
        Verify claim_host uses single atomic UPDATE returning True only on first claim,
        and False for any subsequent claimant.
        """
        ip = "172.16.0.5"
        state.add_host(ip, db_path=self.db_path)

        # Agent Alpha claims first -> should win
        won_alpha = state.claim_host(ip, "agent-alpha", db_path=self.db_path)
        self.assertTrue(won_alpha)

        # Verify host record updated
        host = state.get_host(ip, db_path=self.db_path)
        self.assertEqual(host["status"], "claimed")
        self.assertEqual(host["claimed_by"], "agent-alpha")

        # Agent Beta tries to claim the same host -> should lose
        won_beta = state.claim_host(ip, "agent-beta", db_path=self.db_path)
        self.assertFalse(won_beta)

        # Verify owner did not change
        host_after = state.get_host(ip, db_path=self.db_path)
        self.assertEqual(host_after["claimed_by"], "agent-alpha")
        self.assertEqual(host_after["status"], "claimed")

        # Claiming non-existent host returns False
        self.assertFalse(state.claim_host("255.255.255.255", "agent-alpha", db_path=self.db_path))

    def test_concurrent_multi_agent_race(self):
        """Simulate high-concurrency race across 20 threads for a single host."""
        ip = "10.0.0.99"
        state.add_host(ip, db_path=self.db_path)

        num_agents = 20
        results = []

        def _race_claim(agent_idx: int):
            agent_id = f"worker-{agent_idx}"
            return state.claim_host(ip, agent_id, db_path=self.db_path)

        with ThreadPoolExecutor(max_workers=num_agents) as executor:
            futures = [executor.submit(_race_claim, i) for i in range(num_agents)]
            results = [f.result() for f in futures]

        # Exactly 1 winner
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), num_agents - 1)

        host = state.get_host(ip, db_path=self.db_path)
        self.assertEqual(host["status"], "claimed")
        self.assertTrue(host["claimed_by"].startswith("worker-"))

    def test_append_tested_surface(self):
        """Verify helper function appends values into host tested_surfaces JSON array."""
        ip = "10.20.30.40"
        state.add_host(ip, db_path=self.db_path)

        # Append first surface
        res1 = state.append_tested_surface(ip, "port-80-http", db_path=self.db_path)
        self.assertTrue(res1)
        host = state.get_host(ip, db_path=self.db_path)
        self.assertEqual(host["tested_surfaces"], ["port-80-http"])

        # Append second surface
        res2 = state.append_tested_surface(ip, "port-445-smb", db_path=self.db_path)
        self.assertTrue(res2)
        host = state.get_host(ip, db_path=self.db_path)
        self.assertEqual(host["tested_surfaces"], ["port-80-http", "port-445-smb"])

        # Deduplication flag (allow_duplicates=False)
        res_dup = state.append_tested_surface(ip, "port-80-http", allow_duplicates=False, db_path=self.db_path)
        self.assertFalse(res_dup)
        host = state.get_host(ip, db_path=self.db_path)
        self.assertEqual(host["tested_surfaces"], ["port-80-http", "port-445-smb"])

        # Non-existent host returns False
        self.assertFalse(state.append_tested_surface("0.0.0.0", "web", db_path=self.db_path))

    def test_findings_lifecycle_and_verification(self):
        """Verify insert_finding, auto-increment, default unverified, and verification updates."""
        ip = "192.168.10.100"
        state.add_host(ip, db_path=self.db_path)

        # Insert finding
        finding_id = state.insert_finding(
            host_id=ip,
            surface="web-login",
            type="sql_injection",
            ptes_phase="Exploitation",
            description="Blind boolean-based SQL injection on /login username parameter",
            evidence="HTTP 200 on admin' AND 1=1-- vs HTTP 401 on admin' AND 1=2--",
            severity="high",
            db_path=self.db_path
        )
        self.assertIsInstance(finding_id, int)
        self.assertGreater(finding_id, 0)

        # Retrieve and verify default status
        finding = state.get_finding(finding_id, db_path=self.db_path)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["host_id"], ip)
        self.assertEqual(finding["surface"], "web-login")
        self.assertEqual(finding["type"], "sql_injection")
        self.assertEqual(finding["verified"], "unverified")  # Default requirement
        self.assertEqual(finding["severity"], "high")

        # Update verification status using default (confirmed)
        updated = state.update_finding_verification(finding_id, db_path=self.db_path)
        self.assertTrue(updated)

        finding_updated = state.get_finding(finding_id, db_path=self.db_path)
        self.assertEqual(finding_updated["verified"], "confirmed")

        # Update verification status to 'probable'
        updated_prob = state.update_finding_verification(finding_id, "probable", db_path=self.db_path)
        self.assertTrue(updated_prob)
        self.assertEqual(state.get_finding(finding_id, db_path=self.db_path)["verified"], "probable")

        # Update verification status back to 'unverified'
        updated_unv = state.update_finding_verification(finding_id, "unverified", db_path=self.db_path)
        self.assertTrue(updated_unv)
        self.assertEqual(state.get_finding(finding_id, db_path=self.db_path)["verified"], "unverified")

        # Disallowed states must raise ValueError
        for invalid_status in ["verified", "false_positive", "exploited", "invalid_status"]:
            with self.assertRaises(ValueError):
                state.update_finding_verification(finding_id, invalid_status, db_path=self.db_path)
            with self.assertRaises(ValueError):
                state.insert_finding(host_id=ip, verified=invalid_status, db_path=self.db_path)

        # Update non-existent finding
        self.assertFalse(state.update_finding_verification(99999, "confirmed", db_path=self.db_path))

    def test_attack_path_progression(self):
        """Verify attack_path recording step, finding_id, leads_to_finding_id, and notes."""
        ip = "10.10.10.200"
        state.add_host(ip, db_path=self.db_path)

        f1 = state.insert_finding(
            host_id=ip,
            surface="web-drupal",
            type="rce",
            ptes_phase="Vulnerability Analysis",
            description="Drupalgeddon2 CVE-2018-7600",
            db_path=self.db_path
        )

        f2 = state.insert_finding(
            host_id=ip,
            surface="internal-network",
            type="credential_dump",
            ptes_phase="Post-Exploitation",
            description="Extracted database root password from settings.php",
            db_path=self.db_path
        )

        # Record attack path step
        state.add_attack_path_step(
            step=1,
            finding_id=f1,
            leads_to_finding_id=f2,
            notes="Leveraged Drupal RCE to drop web shell and dump DB config",
            db_path=self.db_path
        )

        path = state.get_attack_path(db_path=self.db_path)
        self.assertEqual(len(path), 1)
        step1 = path[0]
        self.assertEqual(step1["step"], 1)
        self.assertEqual(step1["finding_id"], f1)
        self.assertEqual(step1["leads_to_finding_id"], f2)
        self.assertEqual(step1["finding_description"], "Drupalgeddon2 CVE-2018-7600")
        self.assertEqual(step1["leads_to_description"], "Extracted database root password from settings.php")

    def test_foreign_key_enforcement(self):
        """Ensure findings cannot reference non-existent hosts."""
        with self.assertRaises(sqlite3.IntegrityError):
            state.insert_finding(
                host_id="non.existent.host",
                description="Ghost finding",
                db_path=self.db_path
            )


if __name__ == "__main__":
    unittest.main()

