"""
Unit tests for verifier.py (Finding re-check logic, 3-state vocabulary enforcement, and state persistence).
"""

import json
import os
from pathlib import Path
import tempfile
import unittest

from scope import ScopeGate
import state
from verifier import verify_all_unverified, verify_finding


class TestVerifier(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_verify.db")
        state.init_db(self.db_path)

        self.host_ip = "10.10.10.50"
        state.add_host(self.host_ip, db_path=self.db_path)

        self.scope_config = {
            "network_ranges": ["10.10.10.0/24"],
            "excluded": ["10.10.10.1"],
            "binaries": ["nmap", "file", "strings", "checksec"],
        }
        self.gate = ScopeGate(config_dict=self.scope_config)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_verify_binary_surface_confirmed_directly(self):
        """Any finding where surface is 'binary' is directly marked 'confirmed'."""
        # 1. Exact surface 'binary'
        f1_id = state.insert_finding(
            host_id=self.host_ip,
            surface="binary",
            type="cve_analysis",
            description="Static binary string match",
            db_path=self.db_path,
        )

        status1 = verify_finding(f1_id, gate=self.gate, db_path=self.db_path)
        self.assertEqual(status1, "confirmed")

        # Check persistence
        updated_f1 = state.get_finding(f1_id, db_path=self.db_path)
        self.assertEqual(updated_f1["verified"], "confirmed")

        # 2. Sub-surface starting with 'binary/'
        f2_id = state.insert_finding(
            host_id=self.host_ip,
            surface="binary/sample_bin/secrets",
            type="hardcoded_credential",
            description="Static password match",
            evidence="password=admin123",
            db_path=self.db_path,
        )

        status2 = verify_finding(f2_id, gate=self.gate, db_path=self.db_path)
        self.assertEqual(status2, "confirmed")
        self.assertEqual(state.get_finding(f2_id, db_path=self.db_path)["verified"], "confirmed")

    def test_verify_default_credential_success(self):
        """default_credential sets 'confirmed' when auth request succeeds."""
        evidence = json.dumps({
            "url": f"http://{self.host_ip}/admin",
            "username": "admin",
            "password": "adminpassword",
        })

        fid = state.insert_finding(
            host_id=self.host_ip,
            surface="web/login",
            type="default_credential",
            description="Default admin credential found",
            evidence=evidence,
            db_path=self.db_path,
        )

        def mock_auth_success(url, method="GET", data=None, auth=None, **kwargs):
            self.assertEqual(auth, ("admin", "adminpassword"))
            return 200, "Welcome Administrator Dashboard"

        status = verify_finding(
            fid,
            gate=self.gate,
            db_path=self.db_path,
            requester=mock_auth_success,
        )
        self.assertEqual(status, "confirmed")
        self.assertEqual(state.get_finding(fid, db_path=self.db_path)["verified"], "confirmed")

    def test_verify_default_credential_failure(self):
        """default_credential sets 'unverified' when auth request fails."""
        evidence = "admin:wrongpassword"

        fid = state.insert_finding(
            host_id=self.host_ip,
            surface="web/login",
            type="default_credential",
            description="Default admin credential attempt",
            evidence=evidence,
            db_path=self.db_path,
        )

        def mock_auth_fail(url, method="GET", data=None, auth=None, **kwargs):
            return 401, "Unauthorized: Invalid credentials"

        status = verify_finding(
            fid,
            gate=self.gate,
            db_path=self.db_path,
            requester=mock_auth_fail,
        )
        self.assertEqual(status, "unverified")
        self.assertEqual(state.get_finding(fid, db_path=self.db_path)["verified"], "unverified")

    def test_verify_reflected_xss_confirmed(self):
        """reflected_xss sets 'confirmed' when expected marker appears in response body."""
        marker = "<script>alert('XSS')</script>"
        evidence = json.dumps({
            "url": f"http://{self.host_ip}/search?q={marker}",
            "payload": marker,
            "marker": marker,
        })

        fid = state.insert_finding(
            host_id=self.host_ip,
            surface="web/search",
            type="reflected_xss",
            description="Reflected XSS on search parameter",
            evidence=evidence,
            db_path=self.db_path,
        )

        def mock_xss_reflected(url, **kwargs):
            return 200, f"<html>Search results for: {marker}</html>"

        status = verify_finding(
            fid,
            gate=self.gate,
            db_path=self.db_path,
            requester=mock_xss_reflected,
        )
        self.assertEqual(status, "confirmed")
        self.assertEqual(state.get_finding(fid, db_path=self.db_path)["verified"], "confirmed")

    def test_verify_reflected_xss_unverified_when_marker_missing(self):
        """reflected_xss sets 'unverified' when marker is not in response body."""
        marker = "<script>alert('XSS')</script>"
        evidence = f"URL: http://{self.host_ip}/search | Marker: {marker}"

        fid = state.insert_finding(
            host_id=self.host_ip,
            surface="web/search",
            type="reflected_xss",
            description="Reflected XSS test",
            evidence=evidence,
            db_path=self.db_path,
        )

        def mock_xss_sanitized(url, **kwargs):
            # Response encodes/sanitizes payload
            return 200, "<html>Search results for: &lt;script&gt;alert('XSS')&lt;/script&gt;</html>"

        status = verify_finding(
            fid,
            gate=self.gate,
            db_path=self.db_path,
            requester=mock_xss_sanitized,
        )
        self.assertEqual(status, "unverified")
        self.assertEqual(state.get_finding(fid, db_path=self.db_path)["verified"], "unverified")

    def test_verify_sql_injection_confirmed(self):
        """sql_injection sets 'confirmed' when marker (e.g. database error/version) is in response."""
        marker = "syntax error near unexpected token"
        evidence = json.dumps({
            "url": f"http://{self.host_ip}/items?id=1'",
            "payload": "1'",
            "marker": marker,
        })

        fid = state.insert_finding(
            host_id=self.host_ip,
            surface="web/items",
            type="sql_injection",
            description="Error-based SQL injection",
            evidence=evidence,
            db_path=self.db_path,
        )

        def mock_sqli_success(url, **kwargs):
            return 500, f"Database Error: {marker}"

        status = verify_finding(
            fid,
            gate=self.gate,
            db_path=self.db_path,
            requester=mock_sqli_success,
        )
        self.assertEqual(status, "confirmed")
        self.assertEqual(state.get_finding(fid, db_path=self.db_path)["verified"], "confirmed")

    def test_verify_other_types_set_probable(self):
        """Any other finding type must have verified set to 'probable'."""
        other_types = ["service_discovery", "open_port", "cve_2021_44228", "missing_header", "ssl_tls_issue"]

        for o_type in other_types:
            fid = state.insert_finding(
                host_id=self.host_ip,
                surface="network/443-https",
                type=o_type,
                description=f"Generic finding of type {o_type}",
                db_path=self.db_path,
            )

            status = verify_finding(fid, gate=self.gate, db_path=self.db_path)
            self.assertEqual(status, "probable")
            self.assertEqual(state.get_finding(fid, db_path=self.db_path)["verified"], "probable")

    def test_verify_aborts_network_request_for_out_of_scope_target(self):
        """ScopeGate blocks network confirmation for out-of-scope or excluded targets."""
        excluded_ip = "10.10.10.1"
        state.add_host(excluded_ip, db_path=self.db_path)

        fid = state.insert_finding(
            host_id=excluded_ip,
            surface="web/login",
            type="default_credential",
            evidence="admin:admin",
            db_path=self.db_path,
        )

        network_called = False

        def mock_requester(url, **kwargs):
            nonlocal network_called
            network_called = True
            return 200, "OK"

        status = verify_finding(
            fid,
            gate=self.gate,
            db_path=self.db_path,
            requester=mock_requester,
        )

        self.assertFalse(network_called)
        self.assertEqual(status, "unverified")
        self.assertEqual(state.get_finding(fid, db_path=self.db_path)["verified"], "unverified")

    def test_verify_all_unverified(self):
        """Test batch verification of all unverified findings."""
        f1 = state.insert_finding(
            host_id=self.host_ip,
            surface="binary",
            type="static_check",
            db_path=self.db_path,
        )
        f2 = state.insert_finding(
            host_id=self.host_ip,
            surface="network",
            type="service_discovery",
            db_path=self.db_path,
        )

        results = verify_all_unverified(gate=self.gate, db_path=self.db_path)
        self.assertEqual(results[f1], "confirmed")
        self.assertEqual(results[f2], "probable")


if __name__ == "__main__":
    unittest.main()

