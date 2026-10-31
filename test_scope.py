"""
Unit tests for scope.py and @scoped decorator.
"""

import tempfile
import unittest
import yaml

from scope import ScopeGate, scoped


class TestScopeGate(unittest.TestCase):
    def setUp(self):
        self.config_data = {
            "network_ranges": ["10.10.10.0/24", "192.168.1.0/24"],
            "excluded": ["10.10.10.1", "10.10.10.254"],
            "binaries": ["/usr/bin/nmap", "/usr/bin/sqlmap", "nmap.exe", "ping"],
        }
        self.gate = ScopeGate(config_dict=self.config_data)

    def test_check_host_allowed(self):
        """Host within allowed CIDR and not excluded should return True without logging violations."""
        self.assertTrue(self.gate.check_host("10.10.10.42"))
        self.assertTrue(self.gate.check_host("192.168.1.100"))
        self.assertEqual(len(self.gate.violations), 0)

    def test_check_host_excluded(self):
        """Host inside allowed CIDR but in excluded list must return False and log a violation."""
        self.assertFalse(self.gate.check_host("10.10.10.1"))
        self.assertEqual(len(self.gate.violations), 1)

        v = self.gate.violations[0]
        self.assertEqual(v["target"], "10.10.10.1")
        self.assertIn("excluded", v["reason"].lower())
        self.assertIn("timestamp", v)

    def test_check_host_out_of_scope(self):
        """Host outside any allowed range must return False and log a violation."""
        self.assertFalse(self.gate.check_host("8.8.8.8"))
        self.assertFalse(self.gate.check_host("172.16.1.5"))
        self.assertEqual(len(self.gate.violations), 2)

        v1 = self.gate.violations[0]
        self.assertEqual(v1["target"], "8.8.8.8")
        self.assertIn("out of scope", v1["reason"].lower())

    def test_check_host_malformed(self):
        """Malformed IP strings must return False and log a violation."""
        self.assertFalse(self.gate.check_host("not-an-ip"))
        self.assertFalse(self.gate.check_host("999.999.999.999"))
        self.assertEqual(len(self.gate.violations), 2)
        self.assertIn("malformed", self.gate.violations[0]["reason"].lower())

    def test_check_binary_allowed(self):
        """Allowed binaries return True without logging violations."""
        self.assertTrue(self.gate.check_binary("/usr/bin/nmap"))
        self.assertTrue(self.gate.check_binary("nmap.exe"))
        self.assertTrue(self.gate.check_binary("ping"))
        self.assertEqual(len(self.gate.violations), 0)

    def test_check_binary_disallowed(self):
        """Disallowed binary returns False and records a violation."""
        self.assertFalse(self.gate.check_binary("/usr/bin/nc"))
        self.assertFalse(self.gate.check_binary("powershell.exe"))
        self.assertEqual(len(self.gate.violations), 2)

        v = self.gate.violations[0]
        self.assertEqual(v["target"], "/usr/bin/nc")
        self.assertIn("not in the allowed", v["reason"].lower())
        self.assertIn("timestamp", v)

    def test_scoped_decorator_allowed(self):
        """@scoped function executes normally when given an in-scope IP."""
        @self.gate.scoped
        def scan(ip: str, port: int) -> dict:
            return {"ip": ip, "port": port, "open": True}

        result = scan("10.10.10.15", 80)
        self.assertEqual(result, {"ip": "10.10.10.15", "port": 80, "open": True})
        self.assertEqual(len(self.gate.violations), 0)

    def test_scoped_decorator_blocked(self):
        """@scoped function returns None and does not execute body when target is out of scope."""
        executed = False

        @scoped(gate=self.gate)
        def exploit(ip: str) -> str:
            nonlocal executed
            executed = True
            return "pwned"

        # Excluded IP
        res_ex = exploit("10.10.10.1")
        self.assertIsNone(res_ex)
        self.assertFalse(executed)
        self.assertEqual(len(self.gate.violations), 1)

        # Out-of-scope IP
        res_out = exploit("1.1.1.1")
        self.assertIsNone(res_out)
        self.assertFalse(executed)
        self.assertEqual(len(self.gate.violations), 2)

    def test_scoped_decorator_class_method(self):
        """@scoped wraps class methods where self is first argument and ip is second."""
        class PortScanner:
            def __init__(self, gate):
                self.gate = gate

            @scoped(gate=self.gate)
            def scan_host(self, host: str) -> str:
                return f"Scanned {host}"

        scanner = PortScanner(self.gate)
        self.assertEqual(scanner.scan_host("10.10.10.20"), "Scanned 10.10.10.20")
        self.assertIsNone(scanner.scan_host("8.8.8.8"))
        self.assertEqual(len(self.gate.violations), 1)

    def test_yaml_file_loading(self):
        """Test loading directly from a temporary YAML file."""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.dump(self.config_data, f)
            temp_path = f.name

        gate = ScopeGate(config_path=temp_path)
        self.assertTrue(gate.check_host("10.10.10.25"))
        self.assertFalse(gate.check_host("10.10.10.1"))
        self.assertTrue(gate.check_binary("/usr/bin/nmap"))


if __name__ == "__main__":
    unittest.main()

