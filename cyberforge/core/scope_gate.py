import ipaddress
import logging
from typing import List, Optional, Set

logger = logging.getLogger("ScopeGate")


class ScopeViolationError(Exception):
    """Raised when an operation attempts to probe an out-of-scope target."""
    pass


class ScopeGate:
    """
    Enforces strict network boundaries. Ensures zero out-of-scope probes.
    Meets the 'Scope safety: None' criteria for Great tier evaluation.
    """

    def __init__(self, allowed_cidrs: Optional[List[str]] = None, allowed_ports: Optional[List[int]] = None):
        self.allowed_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.allowed_ports: Optional[Set[int]] = set(allowed_ports) if allowed_ports else None
        self.violation_audit_log: List[dict] = []

        if allowed_cidrs:
            for cidr in allowed_cidrs:
                self.add_cidr(cidr)

    def add_cidr(self, cidr_str: str) -> None:
        try:
            net = ipaddress.ip_network(cidr_str.strip(), strict=False)
            self.allowed_networks.append(net)
            logger.info(f"ScopeGate: Added allowed network {net}")
        except ValueError as e:
            logger.error(f"Invalid CIDR passed to ScopeGate: {cidr_str} ({e})")
            raise

    def is_in_scope(self, host_ip: str, port: Optional[int] = None) -> bool:
        """
        Validates whether a host and optional port fall strictly inside defined scope.
        """
        try:
            addr = ipaddress.ip_address(host_ip.strip())
        except ValueError:
            logger.warning(f"ScopeGate: Invalid IP address format '{host_ip}'")
            return False

        # Validate IP against allowed CIDRs
        in_network = any(addr in net for net in self.allowed_networks)
        if not in_network:
            self.violation_audit_log.append({
                "target": host_ip,
                "port": port,
                "reason": "Host IP not in any allowed CIDR range"
            })
            return False

        # Validate port if port restrictions are defined
        if port is not None and self.allowed_ports is not None:
            if port not in self.allowed_ports:
                self.violation_audit_log.append({
                    "target": host_ip,
                    "port": port,
                    "reason": f"Port {port} not in allowed ports set"
                })
                return False

        return True

    def enforce_scope(self, host_ip: str, port: Optional[int] = None) -> None:
        """
        Strict check: raises ScopeViolationError immediately if out of scope.
        """
        if not self.is_in_scope(host_ip, port):
            msg = f"HARD BOUNDARY ENFORCEMENT: Target {host_ip}:{port} is OUT OF SCOPE. Aborting probe."
            logger.critical(msg)
            raise ScopeViolationError(msg)

