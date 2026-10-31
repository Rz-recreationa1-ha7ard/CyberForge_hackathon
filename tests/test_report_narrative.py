"""
Unit tests for ReportGenerator._build_attack_narrative().

Verifies:
- Severity ordering (critical before high before medium)
- Low-only hosts are excluded from the narrative
- Max-steps cap is respected
- One narrative step per host (best finding only)
- Correct severity labels and finding types in output
- Empty narrative when no confirmed/medium+ findings exist
"""

import unittest
from datetime import datetime, timezone
from cyberforge.reporting.generator import ReportGenerator
from cyberforge.core.models import FindingStatus, PTESPhase, SurfaceType
from cyberforge.core.state import SharedState
from cyberforge.core.scope_gate import ScopeGate


def _make_finding(
    host_ip: str,
    finding_type: str,
    verified: bool = True,
    status: str = "CONFIRMED",
    port: int = 80,
    flag: str = None,
) -> dict:
    return {
        "id": f"find-{host_ip}-{finding_type}",
        "host_id": f"host-{host_ip}",
        "host_ip": host_ip,
        "port": port,
        "surface": "web",
        "ptes_phase": PTESPhase.VULNERABILITY_ANALYSIS.value,
        "finding_type": finding_type,
        "title": f"Test finding: {finding_type}",
        "description": "Test",
        "evidence": "Test evidence",
        "verified": verified,
        "status": status,
        "remediation": "Fix it.",
        "flag": flag,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _make_generator() -> ReportGenerator:
    scope_gate = ScopeGate(allowed_cidrs=["192.168.60.0/24"])
    state = SharedState(scope_gate=scope_gate)
    return ReportGenerator(state=state, project_name="Test", tier="recon",
                           allowed_cidrs=["192.168.60.0/24"])


class TestBuildAttackNarrative(unittest.TestCase):

    def test_empty_when_no_confirmed_findings(self):
        gen = _make_generator()
        findings = [
            _make_finding("192.168.60.1", "missing_header", verified=False, status="FLAGGED"),
        ]
        result = gen._build_attack_narrative(findings)
        self.assertEqual(result, [])

    def test_low_severity_only_excluded(self):
        gen = _make_generator()
        findings = [
            _make_finding("192.168.60.1", "missing_header"),   # low
            _make_finding("192.168.60.1", "discovered_form"),  # low/recon
        ]
        result = gen._build_attack_narrative(findings)
        self.assertEqual(result, [])

    def test_critical_before_high_before_medium(self):
        gen = _make_generator()
        findings = [
            _make_finding("192.168.60.10", "sql_injection_error"),        # medium
            _make_finding("192.168.60.20", "default_database_credential", port=3306),  # critical
            _make_finding("192.168.60.30", "sql_injection_auth_bypass"),  # high
        ]
        result = gen._build_attack_narrative(findings)

        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["severity"], "critical")
        self.assertEqual(result[0]["host_ip"], "192.168.60.20")
        self.assertEqual(result[1]["severity"], "high")
        self.assertEqual(result[1]["host_ip"], "192.168.60.30")
        self.assertEqual(result[2]["severity"], "medium")
        self.assertEqual(result[2]["host_ip"], "192.168.60.10")

    def test_one_step_per_host_best_finding_wins(self):
        """A host with both critical and medium findings should appear once (critical)."""
        gen = _make_generator()
        findings = [
            _make_finding("192.168.60.10", "missing_header"),             # low — should be ignored
            _make_finding("192.168.60.10", "sql_injection_error"),        # medium
            _make_finding("192.168.60.10", "unauthenticated_redis", port=6379),  # critical
        ]
        result = gen._build_attack_narrative(findings)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["host_ip"], "192.168.60.10")
        self.assertEqual(result[0]["finding_type"], "unauthenticated_redis")
        self.assertEqual(result[0]["severity"], "critical")

    def test_max_steps_cap(self):
        gen = _make_generator()
        # Create 12 hosts each with a critical finding
        findings = [
            _make_finding(f"192.168.60.{i}", "default_database_credential", port=3306)
            for i in range(1, 13)
        ]
        result = gen._build_attack_narrative(findings, max_steps=8)
        self.assertEqual(len(result), 8)

    def test_steps_numbered_sequentially(self):
        gen = _make_generator()
        findings = [
            _make_finding("192.168.60.1", "default_database_credential", port=3306),
            _make_finding("192.168.60.2", "unauthenticated_redis", port=6379),
        ]
        result = gen._build_attack_narrative(findings)
        steps = [r["step"] for r in result]
        self.assertEqual(steps, list(range(1, len(result) + 1)))

    def test_narrative_sentence_contains_host_and_port(self):
        gen = _make_generator()
        findings = [
            _make_finding("192.168.60.55", "unauthenticated_redis", port=6379),
        ]
        result = gen._build_attack_narrative(findings)
        self.assertEqual(len(result), 1)
        sentence = result[0]["narrative_sentence"]
        self.assertIn("192.168.60.55", sentence)
        self.assertIn("6379", sentence)

    def test_flag_captured_finding_includes_flag_in_narrative(self):
        gen = _make_generator()
        findings = [
            _make_finding("192.168.60.5", "flag_captured", port=80,
                          flag="flag{ctf_test_2026}"),
        ]
        result = gen._build_attack_narrative(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "high")
        sentence = result[0]["narrative_sentence"]
        self.assertIn("flag{ctf_test_2026}", sentence)

    def test_recon_types_excluded_entirely(self):
        gen = _make_generator()
        findings = [
            _make_finding("192.168.60.1", "discovered_form"),
            _make_finding("192.168.60.2", "recon_note"),
            _make_finding("192.168.60.3", "smb_null_session", port=445),
        ]
        result = gen._build_attack_narrative(findings)
        # Only the SMB finding should produce a step
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["finding_type"], "smb_null_session")

    def test_finding_id_present_in_output(self):
        gen = _make_generator()
        findings = [
            _make_finding("192.168.60.7", "smb_null_session", port=445),
        ]
        result = gen._build_attack_narrative(findings)
        self.assertIn("finding_id", result[0])
        self.assertEqual(result[0]["finding_id"], "find-192.168.60.7-smb_null_session")

    def test_generate_json_data_includes_attack_narrative_key(self):
        """generate_json_data() must include 'attack_narrative' in its output."""
        gen = _make_generator()
        data = gen.generate_json_data()
        self.assertIn("attack_narrative", data)
        self.assertIsInstance(data["attack_narrative"], list)

    def test_markdown_section_4_is_narrative_not_raw_log(self):
        """Section 4 in the markdown must contain 'Step 1' when narrative is non-empty."""
        scope_gate = ScopeGate(allowed_cidrs=["192.168.60.0/24"])
        state = SharedState(scope_gate=scope_gate)
        from cyberforge.core.models import PortService, SurfaceType as ST, FindingStatus as FS
        host = state.register_or_update_host(
            ip="192.168.60.1",
            ports=[PortService(port=6379, protocol="tcp", service="redis")],
        )
        state.add_finding(
            host_id=host.host_id,
            host_ip="192.168.60.1",
            port=6379,
            surface=ST.NETWORK,
            ptes_phase=PTESPhase.VULNERABILITY_ANALYSIS,
            finding_type="unauthenticated_redis",
            title="Redis: No Auth Required",
            description="PING returned +PONG",
            evidence="Sent PING, got +PONG",
            verified=True,
            status=FS.CONFIRMED,
        )
        gen = ReportGenerator(state=state, project_name="Test", tier="recon",
                              allowed_cidrs=["192.168.60.0/24"])
        md = gen.generate_markdown_report()
        self.assertIn("## 4. Synthesised Attack Path Narrative", md)
        self.assertIn("Step 1", md)
        self.assertIn("192.168.60.1", md)
        # Raw step table (old format) should NOT be present in section 4
        self.assertNotIn("| Step | Target IP | PTES Phase |", md)


if __name__ == "__main__":
    unittest.main()

