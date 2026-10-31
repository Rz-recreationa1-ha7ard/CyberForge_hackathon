"""
scope.py - Scope Enforcement and Audit Gate for Multi-Component Security Automation.

Designed for authorized hackathon/CTF exercises with organizer-defined scope.
Enforces IP network boundaries, IP exclusions, and approved binary execution paths.
Maintains an append-only audit trail of scope violations and provides the @scoped decorator.
"""

from __future__ import annotations

from datetime import datetime, timezone
import functools
import ipaddress
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union
import yaml

DEFAULT_SCOPE_PATH = os.environ.get("CYBERFORGE_SCOPE", "scope.yaml")


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class ScopeGate:
    """
    Scope verification and boundary enforcement gate.

    Loads rules from a YAML configuration containing:
      - network_ranges: List of allowed CIDR ranges (e.g. '10.10.10.0/24')
      - excluded: List of specific IPs (or subnets) to always reject
      - binaries: List of approved executable file paths or command names

    Tracks all rejected authorization attempts in `violations` for audit logging.
    """

    _default_instance: Optional[ScopeGate] = None

    def __init__(
        self,
        config_path: Union[str, Path] = DEFAULT_SCOPE_PATH,
        config_dict: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the ScopeGate from a YAML file or pre-parsed dictionary.

        Parameters:
          config_path: Path to scope.yaml (defaults to 'scope.yaml' or CYBERFORGE_SCOPE).
          config_dict: Optional in-memory dictionary overriding file loading.
        """
        self.config_path: Optional[Path] = Path(config_path) if config_path else None
        self.network_ranges: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self.excluded_ips: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()
        self.excluded_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self.binaries: Set[str] = set()
        self.violations: List[Dict[str, Any]] = []

        if config_dict is not None:
            self._load_from_dict(config_dict)
        elif self.config_path is not None:
            self.load_config(self.config_path)

    @classmethod
    def get_default(cls, config_path: Union[str, Path] = DEFAULT_SCOPE_PATH) -> ScopeGate:
        """Get or initialize the shared singleton ScopeGate instance."""
        if cls._default_instance is None:
            cls._default_instance = cls(config_path=config_path)
        return cls._default_instance

    @classmethod
    def set_default(cls, gate: ScopeGate) -> None:
        """Set the shared singleton ScopeGate instance."""
        cls._default_instance = gate

    def load_config(self, config_path: Union[str, Path]) -> None:
        """Load and parse scope configuration from a YAML file."""
        path = Path(config_path)
        if not path.is_file():
            raise FileNotFoundError(f"Scope configuration file not found: {path.resolve()}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        if not isinstance(data, dict):
            raise ValueError(f"Scope YAML root must be a mapping, got {type(data).__name__}")

        self._load_from_dict(data)

    def _load_from_dict(self, data: Dict[str, Any]) -> None:
        """Internal parser for scope configuration dictionaries."""
        self.network_ranges.clear()
        self.excluded_ips.clear()
        self.excluded_networks.clear()
        self.binaries.clear()

        # 1. Parse network_ranges
        raw_ranges = data.get("network_ranges") or []
        for entry in raw_ranges:
            if not entry:
                continue
            try:
                net = ipaddress.ip_network(str(entry).strip(), strict=False)
                self.network_ranges.append(net)
            except ValueError as e:
                self.record_violation(
                    target=str(entry),
                    reason=f"Invalid network CIDR configuration in scope file: {e}"
                )

        # 2. Parse excluded IPs / ranges
        raw_excluded = data.get("excluded") or []
        for entry in raw_excluded:
            if not entry:
                continue
            entry_str = str(entry).strip()
            if "/" in entry_str:
                try:
                    net = ipaddress.ip_network(entry_str, strict=False)
                    self.excluded_networks.append(net)
                except ValueError:
                    self.record_violation(
                        target=entry_str,
                        reason="Invalid excluded network CIDR in scope file"
                    )
            else:
                try:
                    ip = ipaddress.ip_address(entry_str)
                    self.excluded_ips.add(ip)
                except ValueError:
                    self.record_violation(
                        target=entry_str,
                        reason="Invalid excluded IP address in scope file"
                    )

        # 3. Parse allowed binaries
        raw_binaries = data.get("binaries") or []
        for entry in raw_binaries:
            if not entry:
                continue
            entry_str = str(entry).strip()
            self.binaries.add(entry_str)
            # Normalize path representations for portable cross-platform comparison
            norm = os.path.normpath(entry_str)
            self.binaries.add(norm)
            self.binaries.add(norm.lower())
            try:
                resolved = str(Path(entry_str).resolve())
                self.binaries.add(resolved)
                self.binaries.add(resolved.lower())
            except Exception:
                pass

    def record_violation(self, target: str, reason: str) -> None:
        """
        Record a rejected scope check to the internal audit log.

        Parameters:
          target: Target host IP, binary path, or identifier.
          reason: Explanation for rejection.
        """
        violation = {
            "target": str(target),
            "reason": str(reason),
            "timestamp": utc_now_iso(),
        }
        self.violations.append(violation)

    def check_host(self, ip: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
        """
        Validate whether a host IP is permitted within the authorized scope.

        Returns True ONLY if:
          1. The IP is a valid IPv4 or IPv6 address.
          2. The IP falls inside at least one allowed range in network_ranges.
          3. The IP is NOT listed in the excluded list (or excluded subnets).

        Every rejection is appended to the violations list with target, reason, and timestamp.
        """
        target_str = str(ip).strip() if ip is not None else ""
        if not target_str:
            self.record_violation(target="<empty>", reason="Empty or missing IP address")
            return False

        try:
            addr = ipaddress.ip_address(target_str)
        except ValueError as err:
            self.record_violation(
                target=target_str,
                reason=f"Malformed IP address format: {err}"
            )
            return False

        # Check explicit exclusion
        if addr in self.excluded_ips:
            self.record_violation(
                target=target_str,
                reason=f"Host {target_str} is explicitly listed in excluded IPs"
            )
            return False

        for ex_net in self.excluded_networks:
            if addr in ex_net:
                self.record_violation(
                    target=target_str,
                    reason=f"Host {target_str} falls inside excluded network {ex_net}"
                )
                return False

        # Check inclusion in allowed ranges
        in_range = any(addr in net for net in self.network_ranges)
        if not in_range:
            self.record_violation(
                target=target_str,
                reason=f"Host {target_str} is out of scope (not inside any allowed network range)"
            )
            return False

        return True

    def check_binary(self, path: Union[str, Path]) -> bool:
        """
        Validate whether an executable binary path is authorized for execution.

        Returns True ONLY if the path (or normalized/resolved path) matches an entry
        in the allowed binaries list.

        Every rejection is appended to the violations list with target, reason, and timestamp.
        """
        target_str = str(path).strip() if path is not None else ""
        if not target_str:
            self.record_violation(target="<empty>", reason="Empty or missing binary path")
            return False

        # Check exact match
        if target_str in self.binaries:
            return True

        # Check normalized path
        norm = os.path.normpath(target_str)
        if norm in self.binaries or norm.lower() in self.binaries:
            return True

        # Check resolved path
        try:
            resolved = str(Path(target_str).resolve())
            if resolved in self.binaries or resolved.lower() in self.binaries:
                return True
        except Exception:
            pass

        # Check basename match if configured
        basename = os.path.basename(target_str)
        if basename in self.binaries or basename.lower() in self.binaries:
            return True

        # Rejected
        self.record_violation(
            target=target_str,
            reason=f"Binary '{target_str}' is not in the allowed binaries list"
        )
        return False

    def scoped(self, func: Callable) -> Callable:
        """Decorator method bound directly to this ScopeGate instance."""
        return scoped(func, gate=self)


# ---------------------------------------------------------------------------
# @scoped Decorator
# ---------------------------------------------------------------------------

def scoped(
    func: Optional[Callable] = None,
    *,
    gate: Optional[ScopeGate] = None,
    config_path: Union[str, Path] = DEFAULT_SCOPE_PATH,
) -> Callable:
    """
    Decorator that wraps any function taking a host IP as its first argument.

    Checks the IP against the ScopeGate before allowing the function body to run.
    If the check fails (out of scope, excluded, or malformed), returns None
    and records the violation in the gate's audit log.

    Usage:
      # Using default / shared gate:
      @scoped
      def scan_host(ip: str, port: int):
          ...

      # Using custom gate:
      my_gate = ScopeGate("custom_scope.yaml")
      @scoped(gate=my_gate)
      def probe_host(ip: str):
          ...

      # Or via instance method:
      @my_gate.scoped
      def exploit_host(ip: str):
          ...
    """
    def _decorator(target_func: Callable) -> Callable:
        @functools.wraps(target_func)
        def _wrapper(*args: Any, **kwargs: Any) -> Any:
            active_gate = gate or ScopeGate.get_default(config_path=config_path)

            # Determine the target IP from arguments
            target_ip = None
            if args:
                # Handle both standalone functions func(ip, ...) and methods func(self, ip, ...)
                if isinstance(args[0], (str, ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    target_ip = args[0]
                elif len(args) > 1 and isinstance(args[1], (str, ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    target_ip = args[1]
                else:
                    target_ip = args[0]
            else:
                target_ip = kwargs.get("ip") or kwargs.get("host")

            if target_ip is None or not active_gate.check_host(target_ip):
                return None

            return target_func(*args, **kwargs)

        return _wrapper

    if func is not None:
        return _decorator(func)
    return _decorator

