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


class SharedState:
    """
    Central blackboard / coordinator state store (FR-4).
    Thread-safe storage for hosts, services, findings, and attack paths.
    Enables handoffs and deduplication between specialized agents.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._hosts: Dict[str, TargetHost] = {}  # host_id -> TargetHost
        self._findings: Dict[str, Finding] = {}  # finding_id -> Finding
        self._attack_path: List[AttackPathStep] = []
        self._event_listeners: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}

    # --- Target Management & Coordination (FR-4) ---

    def register_or_update_host(self, ip: str, hostname: Optional[str] = None, ports: Optional[List[PortService]] = None) -> TargetHost:
        with self._lock:
            # Check if host already exists by IP
            for existing in self._hosts.values():
                if existing.ip == ip:
                    if hostname and not existing.hostname:
                        existing.hostname = hostname
                    if ports:
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
                hostname=hostname,
                ports=ports or []
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

    def verify_finding(self, finding_id: str, verified: bool, extra_evidence: Optional[str] = None) -> bool:
        """
        Updates finding status to CONFIRMED (FR-6 verification logic).
        """
        with self._lock:
            finding = self._findings.get(finding_id)
            if not finding:
                return False

            finding.verified = verified
            finding.status = FindingStatus.CONFIRMED if verified else FindingStatus.FLAGGED
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
