import unittest
from cyberforge.core.models import (
    PTESPhase,
    SurfaceType,
    FindingStatus,
    PortService
)
from cyberforge.core.scope_gate import ScopeGate, ScopeViolationError
from cyberforge.core.state import SharedState
from cyberforge.reporting.generator import ReportGenerator


class TestCyberForgeCore(unittest.TestCase):

    def test_scope_gate_enforcement(self):
        gate = ScopeGate(allowed_cidrs=["192.168.10.0/24"])

        # In scope
        self.assertTrue(gate.is_in_scope("192.168.10.15"))
        self.assertTrue(gate.is_in_scope("192.168.10.254"))

        # Out of scope
        self.assertFalse(gate.is_in_scope("192.168.11.1"))
        self.assertFalse(gate.is_in_scope("8.8.8.8"))

        # Enforce check raises ScopeViolationError
        with self.assertRaises(ScopeViolationError):
            gate.enforce_scope("10.0.0.1")

    def test_shared_state_and_coordination(self):
        gate = ScopeGate(allowed_cidrs=["192.168.10.0/24"])
        state = SharedState(scope_gate=gate)

        # Register host
        host = state.register_or_update_host(
            ip="192.168.10.5",
            hostname="target-alpha",
            ports=[PortService(port=80, protocol="tcp", service="http")]
        )
        self.assertEqual(host.ip, "192.168.10.5")

        # Claiming host prevents duplicate work
        claim_success = state.claim_host("web_agent", host.host_id)
        self.assertTrue(claim_success)

        # Another agent trying to claim must fail
        second_claim = state.claim_host("binary_agent", host.host_id)
        self.assertFalse(second_claim)

        # Mark surface tested
        state.mark_surface_tested(host.host_id, "web")
        self.assertTrue(state.is_surface_tested(host.host_id, "web"))

    def test_findings_and_verification(self):
        gate = ScopeGate(allowed_cidrs=["192.168.10.0/24"])
        state = SharedState(scope_gate=gate)
        host = state.register_or_update_host(ip="192.168.10.5")

        # Add finding
        f1 = state.add_finding(
            host_id=host.host_id,
            host_ip=host.ip,
            surface=SurfaceType.WEB,
            finding_type="exposed_panel",
            title="Exposed Admin Panel",
            description="Admin panel reachable without MFA",
            evidence="HTTP 200 on /admin",
            port=80,
            ptes_phase=PTESPhase.VULNERABILITY_ANALYSIS,
            verified=False,
            remediation="Enforce authentication and restrict IP access"
        )
        self.assertEqual(f1.status, FindingStatus.FLAGGED)
        self.assertFalse(f1.verified)

        # Verify finding (FR-6)
        state.verify_finding(f1.id, verified=True, extra_evidence="Confirmed via valid session token")
        verified_f = state.get_findings(host_id=host.host_id)[0]
        self.assertTrue(verified_f.verified)
        self.assertEqual(verified_f.status, FindingStatus.CONFIRMED)
        self.assertIn("Confirmed via valid session token", verified_f.evidence)

    def test_report_generation(self):
        state = SharedState()
        host = state.register_or_update_host(
            ip="192.168.10.20",
            ports=[PortService(port=80, service="http")]
        )
        state.add_finding(
            host_id=host.host_id,
            host_ip=host.ip,
            surface=SurfaceType.WEB,
            finding_type="reflected_param",
            title="Reflected Parameter",
            description="Parameter reflected in body",
            evidence="Echo test",
            port=80
        )
        state.log_step(
            host_ip=host.ip,
            phase=PTESPhase.INTELLIGENCE_GATHERING,
            surface=SurfaceType.NETWORK,
            action_taken="Port scan completed"
        )

        reporter = ReportGenerator(state, project_name="Test Assessment", tier="recon")
        json_data = reporter.generate_json_data()
        self.assertEqual(json_data["summary"]["total_hosts"], 1)
        self.assertEqual(json_data["summary"]["total_findings"], 1)

        md = reporter.generate_markdown_report()
        self.assertIn("Test Assessment", md)
        self.assertIn("Security Assessment Report", md)
        self.assertIn("192.168.10.20", md)


if __name__ == "__main__":
    unittest.main()

