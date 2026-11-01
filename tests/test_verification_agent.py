import unittest
from unittest.mock import MagicMock
from cyberforge.core.models import TargetHost, PortService, FindingStatus, SurfaceType, PTESPhase
from cyberforge.core.scope_gate import ScopeGate
from cyberforge.core.state import SharedState
from cyberforge.core.config import AgentConfig
from cyberforge.agents.verification_agent import VerificationAgent


class TestVerificationAgent(unittest.TestCase):

    def test_verify_authentic_exposed_path(self):
        scope_gate = ScopeGate(allowed_cidrs=["192.168.60.0/24"])
        state = SharedState()

        config = AgentConfig(
            name="verification_agent",
            role="Verifier",
            surface="web",
            parameters={"timeout_seconds": 2}
        )
        agent = VerificationAgent(config, state, scope_gate)

        host = state.register_or_update_host(
            ip="192.168.60.25",
            ports=[PortService(port=80, protocol="tcp", service="http")]
        )

        finding = state.add_finding(
            host_id=host.host_id,
            host_ip=host.ip,
            port=80,
            surface=SurfaceType.WEB,
            ptes_phase=PTESPhase.VULNERABILITY_ANALYSIS,
            finding_type="exposed_path",
            title="Potentially Exposed Path: /admin",
            description="Admin endpoint found",
            evidence="URL: http://192.168.60.25:80/admin returned HTTP 200",
            verified=False,
            status=FindingStatus.FLAGGED
        )

        # Mock fetch: Canary returns 404, /admin returns real 200 with admin panel
        def mock_fetch(url: str):
            if "cf_canary" in url:
                return (404, "404 Not Found")
            elif "/admin" in url:
                return (200, "<html><title>Admin Dashboard</title><body>Welcome Administrator</body></html>")
            return None

        agent._fetch = MagicMock(side_effect=mock_fetch)

        # Run verification
        agent.execute(host)

        # Check finding status: must be CONFIRMED (FR-6)
        verified_f = state.get_findings(host_id=host.host_id)[0]
        self.assertTrue(verified_f.verified)
        self.assertEqual(verified_f.status, FindingStatus.CONFIRMED)
        self.assertIn("Active verification confirmed HTTP 200", verified_f.evidence)
        # Simply finding an accessible path without secrets must remain Vulnerability Analysis
        self.assertEqual(verified_f.ptes_phase, PTESPhase.VULNERABILITY_ANALYSIS)

    def test_verify_sensitive_content_elevates_to_exploitation(self):
        scope_gate = ScopeGate(allowed_cidrs=["192.168.60.0/24"])
        state = SharedState()

        config = AgentConfig(
            name="verification_agent",
            role="Verifier",
            surface="web",
            parameters={"timeout_seconds": 2}
        )
        agent = VerificationAgent(config, state, scope_gate)

        host = state.register_or_update_host(
            ip="192.168.60.25",
            ports=[PortService(port=80, protocol="tcp", service="http")]
        )

        finding = state.add_finding(
            host_id=host.host_id,
            host_ip=host.ip,
            port=80,
            surface=SurfaceType.WEB,
            ptes_phase=PTESPhase.VULNERABILITY_ANALYSIS,
            finding_type="exposed_path",
            title="Potentially Exposed Path: /.env",
            description="Environment configuration file",
            evidence="URL: http://192.168.60.25:80/.env returned HTTP 200",
            verified=False,
            status=FindingStatus.FLAGGED
        )

        # Mock fetch: Canary returns 404, /.env returns real credentials
        def mock_fetch(url: str):
            if "cf_canary" in url:
                return (404, "404 Not Found")
            elif "/.env" in url:
                return (200, "APP_ENV=production\nDB_PASSWORD=secret_db_pass_2026\nSECRET_KEY=supersecretkey")
            return None

        agent._fetch = MagicMock(side_effect=mock_fetch)

        # Run verification
        agent.execute(host)

        # Finding must be CONFIRMED and elevated to EXPLOITATION because sensitive content was read
        verified_f = state.get_findings(host_id=host.host_id)[0]
        self.assertTrue(verified_f.verified)
        self.assertEqual(verified_f.status, FindingStatus.CONFIRMED)
        self.assertEqual(verified_f.ptes_phase, PTESPhase.EXPLOITATION)
        self.assertIn("[SENSITIVE DATA EXPOSED]", verified_f.evidence)

    def test_filter_soft_404_false_alarm(self):
        scope_gate = ScopeGate(allowed_cidrs=["192.168.60.0/24"])
        state = SharedState()

        config = AgentConfig(
            name="verification_agent",
            role="Verifier",
            surface="web"
        )
        agent = VerificationAgent(config, state, scope_gate)

        host = state.register_or_update_host(
            ip="192.168.60.30",
            ports=[PortService(port=80, protocol="tcp", service="http")]
        )

        finding = state.add_finding(
            host_id=host.host_id,
            host_ip=host.ip,
            port=80,
            surface=SurfaceType.WEB,
            ptes_phase=PTESPhase.VULNERABILITY_ANALYSIS,
            finding_type="exposed_path",
            title="Potentially Exposed Path: /backup",
            description="Backup directory",
            evidence="URL: http://192.168.60.30:80/backup returned HTTP 200",
            verified=False,
            status=FindingStatus.FLAGGED
        )

        # Mock fetch: Server returns 200 for EVERYTHING (Soft-404)
        generic_404_body = "<html><body>Sorry, page not found!</body></html>"

        def mock_fetch(url: str):
            return (200, generic_404_body)

        agent._fetch = MagicMock(side_effect=mock_fetch)

        # Run verification
        agent.execute(host)

        # Finding must NOT be upgraded to CONFIRMED (filtered out as false alarm)
        filtered_f = state.get_findings(host_id=host.host_id)[0]
        self.assertFalse(filtered_f.verified)
        self.assertEqual(filtered_f.status, FindingStatus.FLAGGED)
        self.assertIn("Soft-404 false alarm detected", filtered_f.evidence)


if __name__ == "__main__":
    unittest.main()

