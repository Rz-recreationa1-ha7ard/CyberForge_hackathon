import unittest
from unittest.mock import MagicMock
from cyberforge.core.models import TargetHost, PortService, SurfaceType, FindingStatus
from cyberforge.core.scope_gate import ScopeGate
from cyberforge.core.state import SharedState
from cyberforge.core.config import AgentConfig
from cyberforge.agents.web_agent import WebAgent, WebSurfaceParser


class TestWebAgent(unittest.TestCase):

    def test_web_surface_parser(self):
        html = """
        <html>
            <body>
                <a href="/dashboard">Dashboard</a>
                <a href="https://other-domain.com/out">External</a>
                <form action="/login" method="POST">
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                </form>
            </body>
        </html>
        """
        parser = WebSurfaceParser("http://127.0.0.1:8080")
        parser.feed(html)

        self.assertIn("http://127.0.0.1:8080/dashboard", parser.links)
        self.assertIn("https://other-domain.com/out", parser.links)
        self.assertEqual(len(parser.forms), 1)
        form = parser.forms[0]
        self.assertEqual(form["action"], "http://127.0.0.1:8080/login")
        self.assertEqual(form["method"], "POST")
        input_names = [i["name"] for i in form["inputs"]]
        self.assertIn("username", input_names)
        self.assertIn("password", input_names)

    def test_web_agent_execution_and_findings(self):
        scope_gate = ScopeGate(allowed_cidrs=["127.0.0.1/32"])
        state = SharedState()

        config = AgentConfig(
            name="web_agent",
            role="Web Surface Analyzer",
            surface="web",
            parameters={"max_crawl_depth": 2, "request_timeout_seconds": 2}
        )

        agent = WebAgent(config, state, scope_gate)

        host = state.register_or_update_host(
            ip="127.0.0.1",
            ports=[PortService(port=8080, protocol="tcp", service="http")]
        )

        # Mock responses from _fetch
        def mock_fetch(url: str):
            if url == "http://127.0.0.1:8080":
                headers = {"Server": "Apache/2.4"}  # Omitting CSP, X-Frame-Options
                body = """
                <html>
                    <body>
                        <a href="/login">Login</a>
                        <!-- flag{web_surface_ctf_solved_2026} -->
                    </body>
                </html>
                """
                return (200, headers, body)
            elif url == "http://127.0.0.1:8080/login":
                headers = {"Content-Type": "text/html"}
                body = """
                <html>
                    <body>
                        <form action="/login_submit" method="POST">
                            <input type="text" name="user" />
                            <input type="password" name="pass" />
                        </form>
                    </body>
                </html>
                """
                return (200, headers, body)
            elif url == "http://127.0.0.1:8080/admin":
                return (200, {}, "Admin dashboard")
            return None

        agent._fetch = MagicMock(side_effect=mock_fetch)

        # Run web agent
        agent.execute(host)

        # Verify surface marked as tested
        self.assertTrue(state.is_surface_tested(host.host_id, "web"))

        findings = state.get_findings(host_id=host.host_id)
        finding_types = {f.finding_type for f in findings}

        # Verify missing headers audit
        self.assertIn("missing_header", finding_types)

        # Verify login form discovered
        self.assertIn("discovered_form", finding_types)

        # Verify exposed path /admin discovered
        self.assertIn("exposed_path", finding_types)

        # Verify CTF flag captured (Bonus B-1)
        self.assertIn("flag_captured", finding_types)
        flag_finding = next(f for f in findings if f.finding_type == "flag_captured")
        self.assertEqual(flag_finding.flag, "flag{web_surface_ctf_solved_2026}")
        self.assertTrue(flag_finding.verified)
        self.assertEqual(flag_finding.status, FindingStatus.CONFIRMED)


if __name__ == "__main__":
    unittest.main()
