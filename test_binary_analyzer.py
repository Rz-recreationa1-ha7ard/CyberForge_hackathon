"""
Unit tests for binary_analyzer.py (static binary analysis, ScopeGate checks, and state integration).
"""

import os
from pathlib import Path
import tempfile
import unittest

from binary_analyzer import (
    analyze_binary,
    has_missing_stack_canary,
    scan_strings_for_secrets,
    scan_strings_for_unsafe_c_functions,
)
from scope import ScopeGate
import state

SAMPLE_STRINGS_OUTPUT = """
/lib64/ld-linux-x86-64.so.2
libc.so.6
strcpy
puts
gets
sprintf
system
exec
__libc_start_main
GLIBC_2.2.5
password=CTF{super_secret_admin_pass}
api_key: "AKIAIOSFODNN7EXAMPLE_SECRET"
AKIAIOSFODNN7EXAMPLE
Usage: %s <input>
Done.
"""

SAMPLE_CHECKSEC_NO_CANARY = """
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   68 Symbols        No    0               2               sample_bin
"""

SAMPLE_CHECKSEC_CANARY_PRESENT = """
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   95 Symbols        Yes   2               2               secure_bin
"""


class TestBinaryAnalyzer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_binary_state.db")
        state.init_db(self.db_path)

        # Create dummy binary file
        self.sample_bin = os.path.join(self.temp_dir.name, "sample_bin")
        with open(self.sample_bin, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00" + SAMPLE_STRINGS_OUTPUT.encode("ascii"))

        self.scope_config = {
            "network_ranges": ["10.10.10.0/24"],
            "excluded": ["10.10.10.1"],
            "binaries": [self.sample_bin, "sample_bin", "file", "strings", "checksec"],
        }
        self.gate = ScopeGate(config_dict=self.scope_config)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_scan_strings_for_secrets(self):
        """Verify regex detection of AWS keys and password/secret assignments with matched text as evidence."""
        secrets = scan_strings_for_secrets(SAMPLE_STRINGS_OUTPUT)
        self.assertGreaterEqual(len(secrets), 2)

        evidences = [s["evidence"] for s in secrets]
        self.assertIn("AKIAIOSFODNN7EXAMPLE", evidences)
        self.assertTrue(any("password=CTF{super_secret_admin_pass}" in ev for ev in evidences))

    def test_scan_strings_for_unsafe_c_functions(self):
        """Verify detection of strcpy, gets, sprintf, system, exec."""
        unsafe = scan_strings_for_unsafe_c_functions(SAMPLE_STRINGS_OUTPUT)
        found_funcs = {u["function"] for u in unsafe}

        expected_funcs = {"strcpy", "gets", "sprintf", "system", "exec"}
        self.assertTrue(expected_funcs.issubset(found_funcs))

    def test_has_missing_stack_canary(self):
        """Verify checksec canary parsing."""
        self.assertTrue(has_missing_stack_canary(SAMPLE_CHECKSEC_NO_CANARY))
        self.assertFalse(has_missing_stack_canary(SAMPLE_CHECKSEC_CANARY_PRESENT))

    def test_analyze_binary_end_to_end(self):
        """Verify full pipeline: ScopeGate check, utility outputs, state recording, and surface marking."""
        def mock_runner(cmd):
            prog = cmd[0]
            if prog == "file":
                return "ELF 64-bit LSB executable, x86-64, dynamically linked"
            elif prog == "strings":
                return SAMPLE_STRINGS_OUTPUT
            elif prog == "checksec":
                return SAMPLE_CHECKSEC_NO_CANARY
            return ""

        host_id = "10.10.10.50"
        res = analyze_binary(
            self.sample_bin,
            host_id=host_id,
            gate=self.gate,
            db_path=self.db_path,
            runner=mock_runner,
        )

        self.assertTrue(res["success"])
        self.assertTrue(res["missing_stack_canary"])
        self.assertGreater(len(res["finding_ids"]), 0)

        # 1. Verify 'binary' marked as tested surface in host record
        host = state.get_host(host_id, db_path=self.db_path)
        self.assertIsNotNone(host)
        self.assertIn("binary", host["tested_surfaces"])

        # 2. Verify Findings in SQLite
        findings = state.list_findings(host_id=host_id, db_path=self.db_path)
        self.assertGreaterEqual(len(findings), 8)  # secrets (2+) + unsafe funcs (5) + canary (1)

        # Verify all findings are tagged 'Vulnerability Analysis'
        for f in findings:
            self.assertEqual(f["ptes_phase"], "Vulnerability Analysis")
            self.assertEqual(f["verified"], "unverified")

        # Verify severities: secrets -> high, unsafe C funcs -> medium, canary -> low
        high_findings = [f for f in findings if f["severity"] == "high"]
        med_findings = [f for f in findings if f["severity"] == "medium"]
        low_findings = [f for f in findings if f["severity"] == "low"]

        self.assertGreaterEqual(len(high_findings), 2)  # AWS key and password assignment
        self.assertEqual(len(med_findings), 5)  # strcpy, gets, sprintf, system, exec
        self.assertEqual(len(low_findings), 1)  # stack canary missing

        # Verify evidence field contains matched text
        canary_finding = low_findings[0]
        self.assertIn("No canary found", canary_finding["evidence"])

    def test_analyze_binary_scope_rejection(self):
        """Verify binary outside authorized ScopeGate is rejected before analysis."""
        disallowed_bin = os.path.join(self.temp_dir.name, "unauthorized_malware")
        with open(disallowed_bin, "wb") as f:
            f.write(b"\x7fELF")

        res = analyze_binary(
            disallowed_bin,
            gate=self.gate,
            db_path=self.db_path,
        )

        self.assertFalse(res["success"])
        self.assertIn("not in the authorized scope", res["error"])
        self.assertEqual(len(self.gate.violations), 1)


if __name__ == "__main__":
    unittest.main()

