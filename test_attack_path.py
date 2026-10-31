"""
Unit tests for build_attack_path() function.
"""

import os
from pathlib import Path
import tempfile
import unittest

from attack_path import build_attack_path, get_attack_path
import state


class TestBuildAttackPath(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_attack_path.db")
        state.init_db(self.db_path)

        self.host_id = "10.10.10.50"
        state.add_host(self.host_id, db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_build_attack_path_empty(self):
        """When no findings exist or none are confirmed, attack path should be empty."""
        res = build_attack_path(db_path=self.db_path)
        self.assertEqual(res, [])
        self.assertEqual(get_attack_path(db_path=self.db_path), [])

    def test_build_attack_path_filters_unconfirmed(self):
        """Findings with verified='unverified' or 'probable' must be excluded."""
        # Unverified finding
        f1 = state.insert_finding(
            host_id=self.host_id,
            surface="web",
            type="recon",
            ptes_phase="Intelligence Gathering",
            verified="unverified",
            timestamp="2026-10-31 08:00:00",
            db_path=self.db_path,
        )

        # Probable finding
        f2 = state.insert_finding(
            host_id=self.host_id,
            surface="web",
            type="cve",
            ptes_phase="Vulnerability Analysis",
            verified="probable",
            timestamp="2026-10-31 08:05:00",
            db_path=self.db_path,
        )

        # Confirmed finding
        f3 = state.insert_finding(
            host_id=self.host_id,
            surface="web",
            type="xss",
            ptes_phase="Exploitation",
            verified="confirmed",
            timestamp="2026-10-31 08:10:00",
            db_path=self.db_path,
        )

        path = build_attack_path(db_path=self.db_path)
        self.assertEqual(len(path), 1)
        self.assertEqual(path[0]["step"], 1)
        self.assertEqual(path[0]["finding_id"], f3)
        self.assertIsNone(path[0]["leads_to_finding_id"])

    def test_build_attack_path_ptes_order_and_timestamps(self):
        """
        Verify findings are sorted:
          1. By PTES phase order:
             Intelligence Gathering -> Vulnerability Analysis -> Exploitation -> Post-Exploitation
          2. By timestamp within the same phase
        And linked linearly:
          leads_to_finding_id points to the next finding, final record has None.
        """
        # Insert findings out of order intentionally:

        # 1. Exploitation phase (should be step 4)
        f_exploit = state.insert_finding(
            host_id=self.host_id,
            surface="web/admin",
            type="sql_injection",
            ptes_phase="Exploitation",
            description="SQLi authentication bypass",
            verified="confirmed",
            timestamp="2026-10-31 09:30:00",
            db_path=self.db_path,
        )

        # 2. Intelligence Gathering phase (should be step 1)
        f_recon = state.insert_finding(
            host_id=self.host_id,
            surface="network/80-http",
            type="service_discovery",
            ptes_phase="Intelligence Gathering",
            description="Discovered open HTTP port 80",
            verified="confirmed",
            timestamp="2026-10-31 09:00:00",
            db_path=self.db_path,
        )

        # 3. Post-Exploitation phase (should be step 5, final step)
        f_post = state.insert_finding(
            host_id=self.host_id,
            surface="system",
            type="credential_dump",
            ptes_phase="Post-Exploitation",
            description="Extracted shadow hashes",
            verified="confirmed",
            timestamp="2026-10-31 09:50:00",
            db_path=self.db_path,
        )

        # 4. Vulnerability Analysis phase - early timestamp (should be step 2)
        f_vuln1 = state.insert_finding(
            host_id=self.host_id,
            surface="web/admin",
            type="vulnerability_scan",
            ptes_phase="Vulnerability Analysis",
            description="Identified potential SQLi parameter",
            verified="confirmed",
            timestamp="2026-10-31 09:10:00",
            db_path=self.db_path,
        )

        # 5. Vulnerability Analysis phase - later timestamp (should be step 3)
        f_vuln2 = state.insert_finding(
            host_id=self.host_id,
            surface="web/admin",
            type="error_analysis",
            ptes_phase="Vulnerability Analysis",
            description="Confirmed syntax error in SQL response",
            verified="confirmed",
            timestamp="2026-10-31 09:15:00",
            db_path=self.db_path,
        )

        # Build attack path
        path = build_attack_path(db_path=self.db_path)
        self.assertEqual(len(path), 5)

        # Step 1: Intelligence Gathering (f_recon) -> leads to f_vuln1
        self.assertEqual(path[0]["step"], 1)
        self.assertEqual(path[0]["finding_id"], f_recon)
        self.assertEqual(path[0]["leads_to_finding_id"], f_vuln1)

        # Step 2: Vulnerability Analysis earlier (f_vuln1) -> leads to f_vuln2
        self.assertEqual(path[1]["step"], 2)
        self.assertEqual(path[1]["finding_id"], f_vuln1)
        self.assertEqual(path[1]["leads_to_finding_id"], f_vuln2)

        # Step 3: Vulnerability Analysis later (f_vuln2) -> leads to f_exploit
        self.assertEqual(path[2]["step"], 3)
        self.assertEqual(path[2]["finding_id"], f_vuln2)
        self.assertEqual(path[2]["leads_to_finding_id"], f_exploit)

        # Step 4: Exploitation (f_exploit) -> leads to f_post
        self.assertEqual(path[3]["step"], 4)
        self.assertEqual(path[3]["finding_id"], f_exploit)
        self.assertEqual(path[3]["leads_to_finding_id"], f_post)

        # Step 5: Post-Exploitation (f_post) -> final record has None
        self.assertEqual(path[4]["step"], 5)
        self.assertEqual(path[4]["finding_id"], f_post)
        self.assertIsNone(path[4]["leads_to_finding_id"])

        # Check that get_attack_path joins correctly
        db_path_rows = get_attack_path(db_path=self.db_path)
        self.assertEqual(len(db_path_rows), 5)
        self.assertEqual(db_path_rows[0]["finding_description"], "Discovered open HTTP port 80")
        self.assertEqual(db_path_rows[0]["leads_to_description"], "Identified potential SQLi parameter")
        self.assertIsNone(db_path_rows[4]["leads_to_finding_id"])

    def test_build_attack_path_rebuild_idempotency(self):
        """Calling build_attack_path multiple times cleanly overwrites the sequence without duplicating steps."""
        f1 = state.insert_finding(
            host_id=self.host_id,
            ptes_phase="Intelligence Gathering",
            verified="confirmed",
            db_path=self.db_path,
        )
        f2 = state.insert_finding(
            host_id=self.host_id,
            ptes_phase="Exploitation",
            verified="confirmed",
            db_path=self.db_path,
        )

        build_attack_path(db_path=self.db_path)
        first_count = len(get_attack_path(db_path=self.db_path))
        self.assertEqual(first_count, 2)

        # Re-run build_attack_path
        build_attack_path(db_path=self.db_path)
        second_count = len(get_attack_path(db_path=self.db_path))
        self.assertEqual(second_count, 2)


if __name__ == "__main__":
    unittest.main()

