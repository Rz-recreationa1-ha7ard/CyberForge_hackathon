import unittest
from unittest.mock import MagicMock, patch
from cyberforge.core.models import TargetHost, PortService, PTESPhase, FindingStatus
from cyberforge.core.scope_gate import ScopeGate
from cyberforge.core.state import SharedState
from cyberforge.core.config import AgentConfig
from cyberforge.agents.network_agent import NetworkDiscoveryAgent, MAC_OUI_VENDORS


class TestNetworkAgent(unittest.TestCase):

    def test_network_agent_in_scope_and_discovery(self):
        scope_gate = ScopeGate(allowed_cidrs=["192.168.60.0/24"])
        state = SharedState(scope_gate=scope_gate)

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
        state = SharedState(scope_gate=scope_gate)

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

    def test_mac_and_vendor_resolution(self):
        scope_gate = ScopeGate(allowed_cidrs=["192.168.60.0/24"])
        state = SharedState(scope_gate=scope_gate)

        config = AgentConfig(
            name="network_discovery",
            role="Network Scanner",
            surface="network",
            parameters={"ports": [80]}
        )
        agent = NetworkDiscoveryAgent(config, state, scope_gate)

        # Test static vendor mapping
        self.assertEqual(agent._resolve_vendor("00:50:56:11:22:33"), "VMware")
        self.assertEqual(agent._resolve_vendor("08:00:27:aa:bb:cc"), "Oracle VirtualBox")
        self.assertEqual(agent._resolve_vendor("dc:62:79:b7:33:7e"), "Ubiquiti Networks")
        self.assertEqual(agent._resolve_vendor("a0:59:50:5b:78:c7"), "Intel Corporate")
        self.assertEqual(agent._resolve_vendor("4e:f1:7c:c1:57:c5"), "Locally Administered (Private MAC)")
        self.assertEqual(agent._resolve_vendor("ff:ff:ff:11:22:33"), "Multicast / Broadcast Address")
        self.assertEqual(agent._resolve_vendor("00:ff:ff:11:22:33"), "Unknown Vendor")

        # Test execution populates MAC and vendor on discovered host
        def mock_check_port(ip, port):
            if ip == "192.168.60.10":
                return PortService(port=80, protocol="tcp", service="http")
            return None

        agent._check_port = MagicMock(side_effect=mock_check_port)
        agent._resolve_mac = MagicMock(return_value="00:50:56:ab:cd:ef")

        dummy_target = TargetHost(host_id="net-test", ip="192.168.60.10/32")
        agent.execute(dummy_target)

        hosts = state.list_hosts()
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].mac_address, "00:50:56:ab:cd:ef")
        self.assertEqual(hosts[0].mac_vendor, "VMware")
        self.assertIn("network", hosts[0].tested_surfaces)

    def test_ctf_flag_captured_in_service_banner(self):
        scope_gate = ScopeGate(allowed_cidrs=["192.168.60.0/24"])
        state = SharedState(scope_gate=scope_gate)

        config = AgentConfig(
            name="network_discovery",
            role="Network Scanner",
            surface="network",
            parameters={"ports": [22]}
        )
        agent = NetworkDiscoveryAgent(config, state, scope_gate)

        flag_val = "flag{ssh_banner_captured_2026}"
        def mock_check_port(ip, port):
            if ip == "192.168.60.15":
                return PortService(port=22, protocol="tcp", service="ssh", version=f"SSH-2.0-OpenSSH {flag_val}")
            return None

        agent._check_port = MagicMock(side_effect=mock_check_port)

        dummy_target = TargetHost(host_id="net-test", ip="192.168.60.15/32")
        agent.execute(dummy_target)

        findings = state.get_findings()
        flag_findings = [f for f in findings if f.finding_type == "flag_captured"]
        self.assertEqual(len(flag_findings), 1)
        self.assertEqual(flag_findings[0].flag, flag_val)
        self.assertTrue(flag_findings[0].verified)
        self.assertEqual(flag_findings[0].status, FindingStatus.CONFIRMED)


if __name__ == "__main__":
    unittest.main()
