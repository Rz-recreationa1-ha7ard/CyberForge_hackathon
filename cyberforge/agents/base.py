from abc import ABC, abstractmethod
import logging
from typing import Any, Dict, Optional
from cyberforge.core.state import SharedState
from cyberforge.core.scope_gate import ScopeGate
from cyberforge.core.models import TargetHost, SurfaceType, PTESPhase
from cyberforge.core.config import AgentConfig


class BaseAgent(ABC):
    """
    Abstract Base Class for all CyberForge agents.
    Enforces scope-checking and standard coordination interfaces.
    """

    def __init__(self, config: AgentConfig, state: SharedState, scope_gate: ScopeGate):
        self.config = config
        self.name = config.name
        self.surface = SurfaceType(config.surface)
        self.state = state
        self.scope_gate = scope_gate
        self.logger = logging.getLogger(f"Agent.{self.name}")

    def is_target_in_scope(self, ip: str, port: Optional[int] = None) -> bool:
        return self.scope_gate.is_in_scope(ip, port)

    def log_ptes_action(self, host_ip: str, phase: PTESPhase, action: str, details: Optional[str] = None) -> None:
        """Helper to record PTES phase actions directly to the shared attack path log."""
        self.state.log_step(
            host_ip=host_ip,
            phase=phase,
            surface=self.surface,
            action_taken=action,
            details=details
        )

    @abstractmethod
    def execute(self, host: TargetHost, **kwargs) -> Any:
        """
        Execute agent tasks against target host.
        Must check scope and handle host claims to avoid duplicate execution.
        """
        pass

