"""
Unit tests for ServiceAuthAgent.

All probes are mocked at the low-level helper function level so no real
network connections are made.  Tests verify that:
  - Correct findings are recorded when default credentials succeed.
  - No findings are recorded when all credential pairs are rejected.
  - The scope gate is respected (out-of-scope hosts are skipped).
  - Finding metadata (type, status, PTES phase, evidence) is correct.
"""

import unittest
from unittest.mock import patch, MagicMock

from cyberforge.core.models import FindingStatus, PortService, PTESPhase, SurfaceType
from cyberforge.core.scope_gate import ScopeGate
from cyberforge.core.state import SharedState
from cyberforge.core.config import AgentConfig
from cyberforge.agents.service_auth_agent import ServiceAuthAgent


def _make_agent(cidr="192.168.60.0/24", timeout=2):
    scope_gate = ScopeGate(allowed_cidrs=[cidr])
    state = SharedState(scope_gate=scope_gate)
    config = AgentConfig(
        name="service_auth_agent",
        role="Service Default-Credential Probe",
        surface="network",
        parameters={"timeout_seconds": timeout},
    )
    agent = ServiceAuthAgent(config, state, scope_gate)
    return agent, state


def _make_host(state, ip, ports):
    return state.register_or_update_host(
        ip=ip,
        ports=[PortService(port=p, protocol="tcp", service="tcp") for p in ports],
    )


class TestMySQLProbe(unittest.TestCase):

    def test_default_cred_accepted_records_finding(self):
        agent, state = _make_agent()
        host = _make_host(state, "192.168.60.10", [3306])

        with patch(
            "cyberforge.agents.service_auth_agent._try_mysql_login",
            return_value=True,
        ):
            agent._probe_mysql(host, 3306)

        findings = state.get_findings(host_id=host.host_id)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.finding_type, "default_database_credential")
        self.assertEqual(f.status, FindingStatus.CONFIRMED)
        self.assertTrue(f.verified)
        self.assertIn("MySQL", f.title)
        self.assertIn("root", f.evidence)           # credential pair in evidence
        self.assertIn("192.168.60.10", f.evidence)

    def test_all_creds_rejected_no_finding(self):
        agent, state = _make_agent()
        host = _make_host(state, "192.168.60.11", [3306])

        with patch(
            "cyberforge.agents.service_auth_agent._try_mysql_login",
            return_value=False,
        ):
            agent._probe_mysql(host, 3306)

        findings = state.get_findings(host_id=host.host_id)
        mysql_findings = [f for f in findings if f.finding_type == "default_database_credential"]
        self.assertEqual(len(mysql_findings), 0)

    def test_only_first_successful_pair_recorded(self):
        """Even if multiple pairs would succeed, only one finding is created."""
        agent, state = _make_agent()
        host = _make_host(state, "192.168.60.12", [3306])

        with patch(
            "cyberforge.agents.service_auth_agent._try_mysql_login",
            return_value=True,
        ):
            agent._probe_mysql(host, 3306)

        findings = [f for f in state.get_findings(host_id=host.host_id)
                    if f.finding_type == "default_database_credential"]
        self.assertEqual(len(findings), 1)


class TestPostgreSQLProbe(unittest.TestCase):

    def test_default_cred_accepted(self):
        agent, state = _make_agent()
        host = _make_host(state, "192.168.60.20", [5432])

        with patch(
            "cyberforge.agents.service_auth_agent._try_postgres_login",
            return_value=True,
        ):
            agent._probe_postgresql(host, 5432)

        findings = [f for f in state.get_findings(host_id=host.host_id)
                    if f.finding_type == "default_database_credential"]
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertIn("PostgreSQL", f.title)
        self.assertEqual(f.ptes_phase, PTESPhase.VULNERABILITY_ANALYSIS)

    def test_no_cred_match_no_finding(self):
        agent, state = _make_agent()
        host = _make_host(state, "192.168.60.21", [5432])

        with patch(
            "cyberforge.agents.service_auth_agent._try_postgres_login",
            return_value=False,
        ):
            agent._probe_postgresql(host, 5432)

        findings = state.get_findings(host_id=host.host_id)
        self.assertEqual(len(findings), 0)


class TestRedisProbe(unittest.TestCase):

    def test_no_auth_accepted_records_finding(self):
        agent, state = _make_agent()
        host = _make_host(state, "192.168.60.30", [6379])

        with patch(
            "cyberforge.agents.service_auth_agent._try_redis_noauth",
            return_value=True,
        ):
            agent._probe_redis(host, 6379)

        findings = state.get_findings(host_id=host.host_id)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.finding_type, "unauthenticated_redis")
        self.assertEqual(f.status, FindingStatus.CONFIRMED)
        self.assertIn("PING", f.evidence)
        self.assertIn("+PONG", f.evidence)

    def test_auth_required_no_finding(self):
        agent, state = _make_agent()
        host = _make_host(state, "192.168.60.31", [6379])

        with patch(
            "cyberforge.agents.service_auth_agent._try_redis_noauth",
            return_value=False,
        ):
            agent._probe_redis(host, 6379)

        self.assertEqual(len(state.get_findings(host_id=host.host_id)), 0)


class TestSMBProbe(unittest.TestCase):

    def test_null_session_accepted_records_finding(self):
        agent, state = _make_agent()
        host = _make_host(state, "192.168.60.40", [445])

        with patch(
            "cyberforge.agents.service_auth_agent._try_smb_null_session",
            return_value=["IPC$", "ADMIN$"],
        ):
            agent._probe_smb(host, 445)

        findings = state.get_findings(host_id=host.host_id)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.finding_type, "smb_null_session")
        self.assertEqual(f.status, FindingStatus.CONFIRMED)
        self.assertIn("IPC$", f.evidence)
        self.assertIn("ADMIN$", f.evidence)

    def test_null_session_rejected_no_finding(self):
        agent, state = _make_agent()
        host = _make_host(state, "192.168.60.41", [445])

        with patch(
            "cyberforge.agents.service_auth_agent._try_smb_null_session",
            return_value=None,
        ):
            agent._probe_smb(host, 445)

        self.assertEqual(len(state.get_findings(host_id=host.host_id)), 0)


class TestTelnetProbe(unittest.TestCase):

    def test_default_cred_accepted_records_finding(self):
        agent, state = _make_agent()
        host = _make_host(state, "192.168.60.50", [23])

        with patch(
            "cyberforge.agents.service_auth_agent._try_telnet_login",
            return_value=True,
        ):
            agent._probe_telnet(host, 23)

        findings = [f for f in state.get_findings(host_id=host.host_id)
                    if f.finding_type == "default_telnet_credential"]
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertIn("Telnet", f.title)
        self.assertEqual(f.status, FindingStatus.CONFIRMED)

    def test_all_creds_rejected_no_finding(self):
        agent, state = _make_agent()
        host = _make_host(state, "192.168.60.51", [23])

        with patch(
            "cyberforge.agents.service_auth_agent._try_telnet_login",
            return_value=False,
        ):
            agent._probe_telnet(host, 23)

        self.assertEqual(len(state.get_findings(host_id=host.host_id)), 0)


class TestExecuteDispatch(unittest.TestCase):

    def test_execute_dispatches_correct_probes(self):
        """execute() calls only the probes matching the host's open ports."""
        agent, state = _make_agent()
        host = _make_host(state, "192.168.60.60", [3306, 6379])

        mysql_mock = MagicMock()
        redis_mock = MagicMock()
        agent._probe_mysql = mysql_mock
        agent._probe_redis = redis_mock
        agent._probe_postgresql = MagicMock()
        agent._probe_smb = MagicMock()
        agent._probe_telnet = MagicMock()

        agent.execute(host)

        mysql_mock.assert_called_once_with(host, 3306)
        redis_mock.assert_called_once_with(host, 6379)
        agent._probe_postgresql.assert_not_called()
        agent._probe_smb.assert_not_called()
        agent._probe_telnet.assert_not_called()

    def test_execute_marks_surface_tested(self):
        agent, state = _make_agent()
        host = _make_host(state, "192.168.60.61", [3306])

        with patch.object(agent, "_probe_mysql"):
            agent.execute(host)

        self.assertTrue(state.is_surface_tested(host.host_id, "service_auth"))

    def test_scope_gate_blocks_out_of_scope_host(self):
        """Hosts outside the CIDR must not be probed."""
        agent, state = _make_agent(cidr="192.168.60.0/24")
        # Bypass scope gate for host registration to directly test execute() behaviour
        from cyberforge.core.models import TargetHost, PortService as PS
        import uuid
        out_host = TargetHost(
            host_id=f"host-{uuid.uuid4().hex[:8]}",
            ip="10.0.0.5",
            ports=[PS(port=3306, protocol="tcp", service="mysql")],
        )
        # Manually insert (bypassing scope gate so we can test agent behaviour)
        with state._lock:
            state._hosts[out_host.host_id] = out_host

        mysql_mock = MagicMock()
        agent._probe_mysql = mysql_mock
        agent.execute(out_host)

        # _probe_mysql must NOT be called since scope gate blocks it
        mysql_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()

