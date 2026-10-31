import logging
import threading
import uuid
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timezone
from cyberforge.core.models import (
    TargetHost,
    Finding,
    FindingStatus,
    PortService,
    SurfaceType,
    PTESPhase,
    AttackPathStep,
)
from cyberforge.core.scope_gate import ScopeGate, ScopeViolationError

logger = logging.getLogger("SharedState")


class SharedState:
    """
    Central blackboard / coordinator state store (FR-4).
    Thread-safe storage for hosts, services, findings, and attack paths.
    Enforces strict scope gatekeeping on all host and finding writes.
    """

    def __init__(self, scope_gate: Optional[ScopeGate] = None):
        self._lock = threading.RLock()
        self.scope_gate = scope_gate
        self._hosts: Dict[str, TargetHost] = {}  # host_id -> TargetHost
        self._findings: Dict[str, Finding] = {}  # finding_id -> Finding
        self._attack_path: List[AttackPathStep] = []
        self._intel: Dict[str, Any] = {}  # Cross-agent shared intelligence blackboard
        self._event_listeners: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}

    def set_intel(self, key: str, value: Any) -> None:
        """Stores shared intelligence or artifacts for cross-agent collaboration (FR-4)."""
        with self._lock:
            self._intel[key] = value

    def get_intel(self, key: str, default: Any = None) -> Any:
        """Retrieves shared intelligence stored by another agent."""
        with self._lock:
            return self._intel.get(key, default)

    # --- Target Management & Coordination (FR-4) ---

    def register_or_update_host(
        self,
        ip: str,
        hostname: Optional[str] = None,
        ports: Optional[List[PortService]] = None,
        mac_address: Optional[str] = None,
        mac_vendor: Optional[str] = None
    ) -> TargetHost:
        with self._lock:
            # Hard Scope Gatekeeper check: Reject out-of-scope host registrations
            if self.scope_gate and not self.scope_gate.is_in_scope(ip):
                msg = f"SCOPE VIOLATION BLOCKED: Host {ip} is OUT OF SCOPE. Registration rejected."
                logger.critical(msg)
                raise ScopeViolationError(msg)
            # Check if host already exists by IP
            for existing in self._hosts.values():
                if existing.ip == ip:
                    if hostname and not existing.hostname:
                        existing.hostname = hostname
                    if mac_address and not existing.mac_address:
                        existing.mac_address = mac_address
                    if mac_vendor and not existing.mac_vendor:
                        existing.mac_vendor = mac_vendor
                    if ports:
                        if "network" not in existing.tested_surfaces:
                            existing.tested_surfaces.append("network")
                        existing_port_nums = {p.port for p in existing.ports}
                        for p in ports:
                            if p.port not in existing_port_nums:
                                existing.ports.append(p)
                    return existing

            # New host
            host_id = f"host-{uuid.uuid4().hex[:8]}"
            target = TargetHost(
                host_id=host_id,
                ip=ip,
                mac_address=mac_address,
                mac_vendor=mac_vendor,
                hostname=hostname,
                ports=ports or [],
                tested_surfaces=["network"] if ports else []
            )
            self._hosts[host_id] = target
            self.emit_event("host_discovered", {"host_id": host_id, "ip": ip})
            return target

    def get_host(self, host_id: str) -> Optional[TargetHost]:
        with self._lock:
            return self._hosts.get(host_id)

    def list_hosts(self) -> List[TargetHost]:
        with self._lock:
            return list(self._hosts.values())

    def claim_host(self, agent_name: str, host_id: str) -> bool:
        """
        Attempts to claim a host for processing.
        Returns False if the host is already tested or currently claimed by another agent.
        """
        with self._lock:
            host = self._hosts.get(host_id)
            if not host:
                return False

            if host.claimed_by and host.claimed_by != agent_name:
                return False

            host.claimed_by = agent_name
            return True

    def release_host(self, host_id: str) -> None:
        with self._lock:
            host = self._hosts.get(host_id)
            if host:
                host.claimed_by = None

    def mark_surface_tested(self, host_id: str, surface: str) -> None:
        with self._lock:
            host = self._hosts.get(host_id)
            if host and surface not in host.tested_surfaces:
                host.tested_surfaces.append(surface)
            if host:
                host.claimed_by = None

    def is_surface_tested(self, host_id: str, surface: str) -> bool:
        with self._lock:
            host = self._hosts.get(host_id)
            if not host:
                return False
            return surface in host.tested_surfaces

    # --- Findings Management (FR-6, FR-7) ---

    def add_finding(
        self,
        host_id: str,
        host_ip: str,
        surface: SurfaceType,
        finding_type: str,
        title: str,
        description: str,
        evidence: str,
        port: Optional[int] = None,
        ptes_phase: PTESPhase = PTESPhase.VULNERABILITY_ANALYSIS,
        verified: bool = False,
        status: FindingStatus = FindingStatus.FLAGGED,
        remediation: Optional[str] = None,
        flag: Optional[str] = None
    ) -> Finding:
        with self._lock:
            # Hard Scope Gatekeeper check: Reject out-of-scope finding writes
            if self.scope_gate and not self.scope_gate.is_in_scope(host_ip, port):
                msg = f"SCOPE VIOLATION BLOCKED: Finding for host {host_ip}:{port} is OUT OF SCOPE. Write rejected."
                logger.critical(msg)
                raise ScopeViolationError(msg)

            # Deduplication: check if same type & target already exists
            for f in self._findings.values():
                if f.host_id == host_id and f.port == port and f.finding_type == finding_type:
                    return f

            fid = f"find-{uuid.uuid4().hex[:8]}"
            finding = Finding(
                id=fid,
                host_id=host_id,
                host_ip=host_ip,
                port=port,
                surface=surface,
                ptes_phase=ptes_phase,
                finding_type=finding_type,
                title=title,
                description=description,
                evidence=evidence,
                verified=verified,
                status=status,
                remediation=remediation,
                flag=flag,
                timestamp=datetime.now(timezone.utc)
            )
            self._findings[fid] = finding
            self.emit_event("finding_added", {"finding": finding.model_dump()})
            return finding

    def get_findings(self, host_id: Optional[str] = None) -> List[Finding]:
        with self._lock:
            if host_id:
                return [f for f in self._findings.values() if f.host_id == host_id]
            return list(self._findings.values())

    def verify_finding(
        self,
        finding_id: str,
        verified: bool,
        extra_evidence: Optional[str] = None,
        ptes_phase: Optional[PTESPhase] = None
    ) -> bool:
        """
        Updates finding status to CONFIRMED (FR-6 verification logic).
        Optionally updates the finding's PTES phase.
        """
        with self._lock:
            finding = self._findings.get(finding_id)
            if not finding:
                return False

            finding.verified = verified
            finding.status = FindingStatus.CONFIRMED if verified else FindingStatus.FLAGGED
            if ptes_phase is not None:
                finding.ptes_phase = ptes_phase
            if extra_evidence:
                finding.evidence = f"{finding.evidence}\n[VERIFICATION]: {extra_evidence}"
            return True

    # --- Attack Path & PTES Sequence Tracking (FR-5, FR-7, B-2) ---

    def log_step(
        self,
        host_ip: str,
        phase: PTESPhase,
        surface: SurfaceType,
        action_taken: str,
        finding_ref: Optional[str] = None,
        details: Optional[str] = None
    ) -> AttackPathStep:
        with self._lock:
            step_num = len(self._attack_path) + 1
            step = AttackPathStep(
                step_number=step_num,
                host_ip=host_ip,
                phase=phase,
                surface=surface,
                action_taken=action_taken,
                finding_ref=finding_ref,
                details=details
            )
            self._attack_path.append(step)
            return step

    def get_attack_path(self) -> List[AttackPathStep]:
        with self._lock:
            return list(self._attack_path)

    # --- Event System for Agent Coordination (FR-4) ---

    def subscribe(self, event_name: str, handler: Callable[[Dict[str, Any]], None]) -> None:
        with self._lock:
            if event_name not in self._event_listeners:
                self._event_listeners[event_name] = []
            self._event_listeners[event_name].append(handler)

    def emit_event(self, event_name: str, data: Dict[str, Any]) -> None:
        with self._lock:
            listeners = list(self._event_listeners.get(event_name, []))
        for listener in listeners:
            try:
                listener(data)
            except Exception:
                pass
