import unittest
from unittest.mock import MagicMock
from cyberforge.core.orchestrator import Orchestrator
from cyberforge.core.models import PortService, FindingStatus
from cyberforge.api.server import get_target_findings, list_all_findings


class TestFullPipeline(unittest.TestCase):

    def test_pipeline_handoff_and_api(self):
        orchestrator = Orchestrator("config.json")

        # Simulate teammate's network discovery finding a host with HTTP port
        target_ip = "192.168.1.50"
        host = orchestrator.state.register_or_update_host(
            ip=target_ip,
            ports=[PortService(port=80, protocol="tcp", service="http")]
        )

        web_agent = orchestrator._agent_registry.get("web_agent")
        self.assertIsNotNone(web_agent)

        # Mock web responses
        def mock_fetch(url: str):
            if url == f"http://{target_ip}:80":
                return (
                    200,
                    {"Server": "nginx"},
                    "<html><body><a href='/admin'>Admin</a> flag{pipeline_verified_flag_2026}</body></html>"
                )
            elif url == f"http://{target_ip}:80/admin":
                return (200, {}, "<html><body><h1>Admin Console</h1></body></html>")
            return None

        web_agent._fetch = MagicMock(side_effect=mock_fetch)

        # Run pipeline
        orchestrator.run_pipeline()

        # Verify host surface marked as tested (FR-4 deduplication)
        self.assertTrue(orchestrator.state.is_surface_tested(host.host_id, "web"))

        # Verify findings were added
        findings = orchestrator.state.get_findings(host_id=host.host_id)
        self.assertGreater(len(findings), 0)

        # Verify API handler (FR-7: GET /targets/{id}/findings)
        api_findings = get_target_findings(host.host_id)
        self.assertEqual(len(api_findings), len(findings))

        # Verify flag captured in findings
        flags = [f["flag"] for f in api_findings if f.get("flag")]
        self.assertIn("flag{pipeline_verified_flag_2026}", flags)


if __name__ == "__main__":
    unittest.main()
