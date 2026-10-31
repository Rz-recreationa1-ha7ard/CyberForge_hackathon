import socket
import ipaddress
import logging
import struct
import sys
import re
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from cyberforge.agents.base import BaseAgent
from cyberforge.core.models import TargetHost, PortService, SurfaceType, PTESPhase, FindingStatus
from cyberforge.core.config import AgentConfig
from cyberforge.core.state import SharedState
from cyberforge.core.scope_gate import ScopeGate


# Curated OUI database for common virtualization, enterprise, and lab hardware
MAC_OUI_VENDORS: Dict[str, str] = {
    # Virtualization & Containers
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU / KVM",
    "00:15:5d": "Microsoft Hyper-V",
    "00:03:ff": "Microsoft Virtual PC",
    "02:42:ac": "Docker Container",
    "00:16:3e": "Xen Virtualization",

    # Networking & Infrastructure
    "00:00:0c": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:01:c7": "Cisco Systems",
    "00:1b:2a": "Cisco Systems",
    "dc:62:79": "Ubiquiti Networks",
    "24:a4:3c": "Ubiquiti Networks",
    "04:18:d6": "Ubiquiti Networks",
    "68:d7:9a": "Ubiquiti Networks",
    "78:8a:20": "Ubiquiti Networks",
    "80:2a:a8": "Ubiquiti Networks",
    "b4:fb:e4": "Ubiquiti Networks",
    "f0:9f:c2": "Ubiquiti Networks",
    "00:14:78": "TP-Link",
    "00:19:e0": "TP-Link",
    "14:cc:20": "TP-Link",
    "50:3e:aa": "TP-Link",
    "ec:08:6b": "TP-Link",
    "24:fe:9a": "CyberTAN Technology",
    "dc:4b:a1": "WNC Corporation",

    # Single-Board Computers & IoT
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "28:cd:c1": "Raspberry Pi",
    "24:0a:c4": "Espressif Systems",
    "24:6f:28": "Espressif Systems",
    "30:ae:a4": "Espressif Systems",
    "84:0d:8e": "Espressif Systems",
    "84:f3:eb": "Espressif Systems",
    "a4:cf:12": "Espressif Systems",

    # Wi-Fi & OEM Connectivity Modules (Lab Devices)
    "f8:3d:c6": "AzureWave Technology",
    "94:bb:43": "AzureWave Technology",
    "1c:ce:51": "AzureWave Technology",
    "60:ff:9e": "AzureWave Technology",
    "cc:47:40": "AzureWave Technology",
    "9c:c7:d3": "AzureWave Technology",
    "90:e8:68": "AzureWave Technology",
    "f0:68:e3": "AzureWave Technology",
    "a8:e2:91": "AzureWave Technology",
    "28:d0:43": "AzureWave Technology",
    "50:5a:65": "AzureWave Technology",
    "f8:54:f6": "AzureWave Technology",
    "f0:a6:54": "Foxconn / Cloud Network Tech",
    "2c:98:11": "Foxconn / Cloud Network Tech",
    "60:e9:aa": "Foxconn / Cloud Network Tech",
    "30:03:c8": "Foxconn / Cloud Network Tech",
    "20:2b:20": "Foxconn / Cloud Network Tech",
    "e8:6f:38": "Foxconn / Fugui Electronics",
    "e0:0a:f6": "Liteon Technology",
    "c0:35:32": "Liteon Technology",
    "24:b2:b9": "Liteon Technology",
    "58:ce:2a": "Liteon Technology",
    "c0:a5:e8": "UIC",

    # Intel Corporate
    "a0:59:50": "Intel Corporate",
    "b0:60:88": "Intel Corporate",
    "60:45:2e": "Intel Corporate",
    "e0:2e:0b": "Intel Corporate",
    "b8:f7:75": "Intel Corporate",
    "28:92:00": "Intel Corporate",
    "28:a4:4a": "Intel Corporate",
    "68:34:21": "Intel Corporate",
    "f8:e4:e3": "Intel Corporate",
    "8c:17:59": "Intel Corporate",
    "e8:c8:29": "Intel Corporate",
    "a0:02:a5": "Intel Corporate",
    "f4:7b:09": "Intel Corporate",
    "38:7a:0e": "Intel Corporate",
    "c8:5e:a9": "Intel Corporate",
    "d4:ab:61": "Intel Corporate",
    "c8:6e:08": "Intel Corporate",
    "e8:bf:b8": "Intel Corporate",
    "98:5f:41": "Intel Corporate",
    "00:02:b3": "Intel Corporate",
    "00:03:47": "Intel Corporate",
    "00:13:e8": "Intel Corporate",
    "00:1b:21": "Intel Corporate",

    # Other Major Hardware Manufacturers
    "00:e0:4c": "Realtek Semiconductor",
    "52:54:4c": "Realtek Semiconductor",
    "00:14:22": "Dell",
    "00:16:f0": "Dell",
    "00:18:8b": "Dell",
    "00:01:e6": "HP / Hewlett Packard",
    "00:02:a5": "HP / Hewlett Packard",
    "00:08:02": "HP / Hewlett Packard",
    "00:03:93": "Apple",
    "00:0a:95": "Apple",
    "ac:bc:32": "Apple",
}

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
    8833: "game-zone",
    8888: "http-jupyter",
    9000: "http-admin",
    9200: "elasticsearch",
    27017: "mongodb"
}


class NetworkDiscoveryAgent(BaseAgent):
    """
    Network Discovery Agent (FR-1).
    Sweeps target CIDR for live hosts, open ports, service banners, MAC addresses and hardware vendors.
    """

    FLAG_PATTERN = re.compile(r"(flag\{[^\s\}]+\}|CTF\{[^\s\}]+\}|MITIGATA\{[^\s\}]+\})", re.IGNORECASE)

    def __init__(self, config: AgentConfig, state: SharedState, scope_gate: ScopeGate):
        super().__init__(config, state, scope_gate)
        self.timeout = self.config.parameters.get("socket_timeout", 0.4)
        self.max_threads = self.config.parameters.get("max_threads", 50)
        self.ports_to_scan = self.config.parameters.get("ports", list(COMMON_PORTS.keys()))

    @staticmethod
    def _resolve_mac(ip: str) -> Optional[str]:
        """
        Resolves MAC address for a target IPv4 address using native OS ARP facilities.
        Zero third-party dependencies required.
        """
        # Windows native ARP via iphlpapi.dll SendARP
        if sys.platform == "win32":
            try:
                import ctypes
                dest_ip = struct.unpack("<I", socket.inet_aton(ip))[0]
                mac_buf = (ctypes.c_byte * 6)()
                mac_len = ctypes.c_ulong(6)
                res = ctypes.windll.iphlpapi.SendARP(
                    dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len)
                )
                if res == 0:
                    mac_bytes = [b & 0xFF for b in mac_buf]
                    if any(mac_bytes):
                        return ":".join(f"{b:02x}" for b in mac_bytes)
            except Exception:
                pass

        # Linux / Unix fallback via /proc/net/arp
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3].lower()
                        if mac != "00:00:00:00:00:00":
                            return mac
        except Exception:
            pass

        return None

    @staticmethod
    def _resolve_vendor(mac: Optional[str]) -> Optional[str]:
        """
        Resolves hardware vendor name from MAC address OUI prefix or LAA flag.
        Accurately identifies Locally Administered (Randomized/Private) MACs vs IEEE assigned vendors.
        """
        if not mac:
            return None

        parts = mac.lower().split(":")
        if len(parts) < 3:
            return None

        # Check IEEE 802 I/G and U/L bits on the first octet
        try:
            first_byte = int(parts[0], 16)
            if first_byte & 0x01:
                return "Multicast / Broadcast Address"
            if first_byte & 0x02:
                return "Locally Administered (Private MAC)"
        except ValueError:
            pass

        oui = ":".join(parts[:3])
        return MAC_OUI_VENDORS.get(oui, "Unknown Vendor")

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
                        version = banner.split("\n")[0][:60]
                        # Check for planted CTF flag in service banner (Bonus B-1)
                        flag_match = self.FLAG_PATTERN.search(banner)
                        if flag_match:
                            flag_str = flag_match.group(1)
                            self.logger.info(f"CAPTURED FLAG (B-1) in {service_name} banner on {ip}:{port}: {flag_str}")
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
                        
                        # Resolve MAC address and hardware vendor for connected device
                        mac = self._resolve_mac(ip)
                        vendor = self._resolve_vendor(mac) if mac else None
                        mac_desc = f" | MAC: {mac} ({vendor})" if mac else ""
                        self.logger.info(f"FOUND LIVE HOST: {ip}{mac_desc} -> Open Ports: [{ports_repr}]")

                        # Register live host in shared blackboard
                        registered = self.state.register_or_update_host(
                            ip=ip,
                            ports=open_ports,
                            mac_address=mac,
                            mac_vendor=vendor
                        )

                        # Explicitly mark network surface as tested
                        self.state.mark_surface_tested(registered.host_id, "network")

                        # Check if any port version captured a CTF flag
                        for p in open_ports:
                            if p.version:
                                flag_match = self.FLAG_PATTERN.search(p.version)
                                if flag_match:
                                    flag_str = flag_match.group(1)
                                    self.state.add_finding(
                                        host_id=registered.host_id,
                                        host_ip=ip,
                                        port=p.port,
                                        surface=SurfaceType.NETWORK,
                                        ptes_phase=PTESPhase.EXPLOITATION,
                                        finding_type="flag_captured",
                                        title=f"Planted CTF Flag Captured in {p.service} banner ({flag_str})",
                                        description=f"Flag found in service banner from {ip}:{p.port}",
                                        evidence=f"Banner: {p.version}",
                                        verified=True,
                                        status=FindingStatus.CONFIRMED,
                                        flag=flag_str,
                                        remediation="Remove sensitive tokens from service banners."
                                    )

                        self.log_ptes_action(
                            host_ip=ip,
                            phase=PTESPhase.INTELLIGENCE_GATHERING,
                            action=f"Host identified as live with open ports: [{ports_repr}]{mac_desc}"
                        )
                except Exception as e:
                    self.logger.debug(f"Scan error on {ip}: {e}")

        self.logger.info(f"Network discovery complete. Discovered {discovered_count} live hosts on {target_cidr}.")
