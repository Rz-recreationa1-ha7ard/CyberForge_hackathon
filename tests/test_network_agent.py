import unittest
from unittest.mock import MagicMock, patch
from cyberforge.core.models import TargetHost, PortService, PTESPhase
from cyberforge.core.scope_gate import ScopeGate
from cyberforge.core.state import SharedState
from cyberforge.core.config import AgentConfig
from cyberforge.agents.network_agent import NetworkDiscoveryAgent


class TestNetworkAgent(unittest.TestCase):

    def test_network_agent_in_scope_and_discovery(self):
        scope_gate = ScopeGate(allowed_cidrs=["192.168.60.0/24"])
        state = SharedState()

        config = AgentConfig(
            name="network_discovery",
            role="Network Scanner",
            surface="network",
            parameters={"socket_timeout": 0.1, "max_threads": 5, "ports": [80, 22]}
        )

        agent = NetworkDiscoveryAgent(config, state, scope_gate)

        # Mock socket connect_ex: simulate 192.168.60.10 has port 80 open
        def mock_check_port(ip, port):
            if ip == "192.168.60.10" and port == 80:
                return PortService(port=80, protocol="tcp", service="http", version="nginx/1.18")
            return None

        agent._check_port = MagicMock(side_effect=mock_check_port)

        # Run execute against a single host or /30 range for fast testing
        dummy_target = TargetHost(host_id="net-test", ip="192.168.60.8/30")
        agent.execute(dummy_target)

        # Verify host registered in shared state
        hosts = state.list_hosts()
        self.assertEqual(len(hosts), 1)
        found_host = hosts[0]
        self.assertEqual(found_host.ip, "192.168.60.10")
        self.assertEqual(len(found_host.ports), 1)
        self.assertEqual(found_host.ports[0].port, 80)
        self.assertEqual(found_host.ports[0].service, "http")

        # Verify PTES logging
        steps = state.get_attack_path()
        self.assertTrue(any(s.phase == PTESPhase.INTELLIGENCE_GATHERING for s in steps))

    def test_scope_gate_blocks_out_of_scope_scan(self):
        scope_gate = ScopeGate(allowed_cidrs=["192.168.60.0/24"])
        state = SharedState()

        config = AgentConfig(
            name="network_discovery",
            role="Network Scanner",
            surface="network",
            parameters={"ports": [80]}
        )
        agent = NetworkDiscoveryAgent(config, state, scope_gate)

        # Target out of scope: 10.0.0.1
        res = agent._check_port("10.0.0.1", 80)
        self.assertIsNone(res)
        self.assertEqual(len(state.list_hosts()), 0)


if __name__ == "__main__":
    unittest.main()
