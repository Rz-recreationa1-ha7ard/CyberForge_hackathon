import socket
import ipaddress
import logging
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from cyberforge.agents.base import BaseAgent
from cyberforge.core.models import TargetHost, PortService, SurfaceType, PTESPhase
from cyberforge.core.config import AgentConfig
from cyberforge.core.state import SharedState
from cyberforge.core.scope_gate import ScopeGate


# Standard service mapping for common lab/CTF ports
COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios",
    443: "https",
    445: "smb",
    1433: "mssql",
    1521: "oracle",
    3000: "http-dev",
    3306: "mysql",
    5000: "http-flask",
    5432: "postgresql",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-jupyter",
    9000: "http-admin",
    9200: "elasticsearch",
    27017: "mongodb"
}


class NetworkDiscoveryAgent(BaseAgent):
    """
    Network Discovery Agent (FR-1).
    Sweeps the target CIDR for live hosts and identifies open services and web entrypoints.
    """

    def __init__(self, config: AgentConfig, state: SharedState, scope_gate: ScopeGate):
        super().__init__(config, state, scope_gate)
        self.timeout = self.config.parameters.get("socket_timeout", 0.4)
        self.max_threads = self.config.parameters.get("max_threads", 50)
        self.ports_to_scan = self.config.parameters.get("ports", list(COMMON_PORTS.keys()))

    def _check_port(self, ip: str, port: int) -> Optional[PortService]:
        """Probes a single TCP port with strict scope verification."""
        if not self.is_target_in_scope(ip, port):
            return None

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            result = s.connect_ex((ip, port))
            if result == 0:
                service_name = COMMON_PORTS.get(port, "unknown")
                version = None

                # Attempt quick banner grab for identification
                try:
                    s.settimeout(0.3)
                    if service_name in ("http", "http-alt", "http-proxy", "http-dev", "http-flask"):
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(256).decode("utf-8", errors="ignore").strip()
                    if banner:
                        # Extract first line of banner
                        version = banner.split("\n")[0][:60]
                except Exception:
                    pass

                return PortService(port=port, protocol="tcp", service=service_name, version=version)
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        return None

    def scan_host(self, ip: str) -> List[PortService]:
        """Scans specified ports on a single IP."""
        open_ports: List[PortService] = []
        for port in self.ports_to_scan:
            res = self._check_port(ip, port)
            if res:
                open_ports.append(res)
        return open_ports

    def execute(self, host: TargetHost, **kwargs) -> None:
        """
        Executes network discovery across the target CIDR scope.
        The host.ip passed can be an individual IP or a full CIDR block.
        """
        target_cidr = host.ip
        self.logger.info(f"Scanning target range {target_cidr} for live hosts and open ports...")
        self.log_ptes_action(
            host_ip=target_cidr,
            phase=PTESPhase.INTELLIGENCE_GATHERING,
            action="Network range discovery and port sweep initiated"
        )

        try:
            net = ipaddress.ip_network(target_cidr, strict=False)
            hosts_to_scan = [str(ip) for ip in net.hosts()]
            # If single IP (/32)
            if not hosts_to_scan:
                hosts_to_scan = [str(net.network_address)]
        except ValueError:
            hosts_to_scan = [target_cidr]

        self.logger.info(f"Probing {len(hosts_to_scan)} potential IP addresses with {self.max_threads} worker threads...")

        discovered_count = 0
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_ip = {
                executor.submit(self.scan_host, ip): ip
                for ip in hosts_to_scan
            }

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    open_ports = future.result()
                    if open_ports:
                        discovered_count += 1
                        ports_repr = ", ".join([f"{p.port}/{p.service}" for p in open_ports])
                        self.logger.info(f"FOUND LIVE HOST: {ip} -> Open Ports: [{ports_repr}]")

                        # Register live host in shared blackboard
                        registered = self.state.register_or_update_host(
                            ip=ip,
                            ports=open_ports
                        )

                        self.log_ptes_action(
                            host_ip=ip,
                            phase=PTESPhase.INTELLIGENCE_GATHERING,
                            action=f"Host identified as live with open ports: {ports_repr}"
                        )
                except Exception as e:
                    self.logger.debug(f"Scan error on {ip}: {e}")

        self.logger.info(f"Network discovery complete. Discovered {discovered_count} live hosts on {target_cidr}.")

