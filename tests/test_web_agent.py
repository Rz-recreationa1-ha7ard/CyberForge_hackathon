import unittest
from unittest.mock import MagicMock, patch
from cyberforge.core.models import TargetHost, PortService, SurfaceType, FindingStatus, PTESPhase
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
        def mock_fetch(url: str, *args, **kwargs):
            if url == "http://127.0.0.1:8080":
                headers = {"Server": "Apache/2.4"}  # Omitting CSP, X-Frame-Options
                body = """
                <html>
                    <body>
                        <a href="/login">Login</a>
                        <a href="/search?q=test">Search</a>
                        <!-- flag{web_surface_ctf_solved_2026} -->
                    </body>
                </html>
                """
                return (200, headers, body)
            elif "/search" in url:
                param_val = url.split("q=")[-1] if "q=" in url else ""
                return (200, {}, f"<html><body>Results for: {param_val}</body></html>")
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
            elif url == "http://127.0.0.1:8080/.env":
                return (200, {}, "APP_ENV=production\nDB_PASSWORD=secret123")
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

        # Verify reflected input discovered (FR-2: a form/param that echoes input)
        self.assertIn("reflected_input", finding_types)

        # Verify exposed path /admin discovered
        self.assertIn("exposed_path", finding_types)

        # Verify CTF flag captured (Bonus B-1)
        self.assertIn("flag_captured", finding_types)
        flag_finding = next(f for f in findings if f.finding_type == "flag_captured")
        self.assertEqual(flag_finding.flag, "flag{web_surface_ctf_solved_2026}")
        self.assertTrue(flag_finding.verified)
        self.assertEqual(flag_finding.status, FindingStatus.CONFIRMED)


class TestSQLiCheck(unittest.TestCase):
    """Unit tests for the _check_sqli method in WebAgent."""

    def _make_agent(self, scope_ip="127.0.0.1", cidr="127.0.0.1/32"):
        scope_gate = ScopeGate(allowed_cidrs=[cidr])
        state = SharedState(scope_gate=scope_gate)
        config = AgentConfig(
            name="web_agent",
            role="Web Surface Analyzer",
            surface="web",
            parameters={"request_timeout_seconds": 2},
        )
        agent = WebAgent(config, state, scope_gate)
        return agent, state

    def _make_host(self, state, ip="127.0.0.1"):
        return state.register_or_update_host(
            ip=ip,
            ports=[PortService(port=80, protocol="tcp", service="http")],
        )

    def _basic_login_form(self, action="http://127.0.0.1:80/login"):
        return {
            "action": action,
            "method": "POST",
            "inputs": [
                {"name": "username", "type": "text", "value": ""},
                {"name": "password", "type": "password", "value": ""},
            ],
        }

    def test_db_error_disclosure_detected(self):
        """A DB error string in the response triggers a sql_injection_error finding."""
        agent, state = self._make_agent()
        host = self._make_host(state)
        form = self._basic_login_form()

        # Baseline returns normal page; quote payload returns DB error
        def mock_submit(action_url, method, inputs, override):
            val = override.get("username", "")
            if val == "'":
                return (200, {}, "<html><body>You have an error in your SQL syntax near '''' at line 1</body></html>")
            return (200, {}, "<html><body>Login</body></html>")

        agent._submit_form = MagicMock(side_effect=mock_submit)
        agent._check_sqli(host, 80, form, is_login=True)

        findings = state.get_findings(host_id=host.host_id)
        sqli_findings = [f for f in findings if f.finding_type == "sql_injection_error"]
        self.assertEqual(len(sqli_findings), 1)
        f = sqli_findings[0]
        self.assertTrue(f.verified)
        self.assertEqual(f.status, FindingStatus.CONFIRMED)
        self.assertEqual(f.ptes_phase, PTESPhase.VULNERABILITY_ANALYSIS)
        self.assertIn("'", f.evidence)              # payload in evidence
        self.assertIn("username", f.evidence)       # field name in evidence
        self.assertIn("sql", f.evidence.lower())    # matched error fragment in evidence

    def test_auth_bypass_detected(self):
        """An always-true tautology that produces a logged-in response triggers auth bypass finding."""
        agent, state = self._make_agent()
        host = self._make_host(state)
        form = self._basic_login_form()

        def mock_submit(action_url, method, inputs, override):
            val = override.get("username", "")
            # Tautology payloads return a "dashboard" page; others return login
            if any(p in val for p in ("OR '1'='1", "OR 1=1", "admin'--")):
                return (200, {}, "<html><body><a href='/logout'>Logout</a> Welcome to your dashboard!</body></html>")
            return (200, {}, "<html><body>Login page</body></html>")

        agent._submit_form = MagicMock(side_effect=mock_submit)
        agent._check_sqli(host, 80, form, is_login=True)

        findings = state.get_findings(host_id=host.host_id)
        bypass_findings = [f for f in findings if f.finding_type == "sql_injection_auth_bypass"]
        self.assertEqual(len(bypass_findings), 1)
        f = bypass_findings[0]
        self.assertTrue(f.verified)
        self.assertEqual(f.status, FindingStatus.CONFIRMED)
        self.assertEqual(f.ptes_phase, PTESPhase.EXPLOITATION)
        self.assertIn("username", f.evidence)

    def test_no_finding_on_clean_form(self):
        """No SQLi findings are raised when the form behaves normally for all payloads."""
        agent, state = self._make_agent()
        host = self._make_host(state)
        form = self._basic_login_form()

        def mock_submit(action_url, method, inputs, override):
            return (200, {}, "<html><body>Invalid credentials</body></html>")

        agent._submit_form = MagicMock(side_effect=mock_submit)
        agent._check_sqli(host, 80, form, is_login=True)

        findings = state.get_findings(host_id=host.host_id)
        sqli_types = {f.finding_type for f in findings}
        self.assertNotIn("sql_injection_error", sqli_types)
        self.assertNotIn("sql_injection_auth_bypass", sqli_types)

    def test_bypass_not_flagged_on_non_login_form(self):
        """Auth bypass finding is NOT raised on a generic (non-login) form."""
        agent, state = self._make_agent()
        host = self._make_host(state)
        # A search form — not a login form
        form = {
            "action": "http://127.0.0.1:80/search",
            "method": "GET",
            "inputs": [{"name": "q", "type": "text", "value": ""}],
        }

        def mock_submit(action_url, method, inputs, override):
            return (200, {}, "<html><body>Welcome to your dashboard!</body></html>")

        agent._submit_form = MagicMock(side_effect=mock_submit)
        agent._check_sqli(host, 80, form, is_login=False)

        findings = state.get_findings(host_id=host.host_id)
        bypass_findings = [f for f in findings if f.finding_type == "sql_injection_auth_bypass"]
        self.assertEqual(len(bypass_findings), 0)


if __name__ == "__main__":
    unittest.main()
