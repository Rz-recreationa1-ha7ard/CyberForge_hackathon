import logging
import threading
import time
import uvicorn
from typing import Dict, List, Type
from cyberforge.core.models import PTESPhase, SurfaceType, TargetHost
from cyberforge.core.scope_gate import ScopeGate
from cyberforge.core.state import SharedState
from cyberforge.core.config import EngineConfig, load_config
from cyberforge.reporting.generator import ReportGenerator
from cyberforge.api.server import app, set_state_reference
from cyberforge.agents.base import BaseAgent

logger = logging.getLogger("Orchestrator")


class Orchestrator:
    """
    Main multi-agent coordinator (FR-4).
    Manages agent lifecycles, event dispatching, deduplication, and scope safety.
    """

    def __init__(self, config_path: str = "config.yaml"):
        self.config: EngineConfig = load_config(config_path)
        self.scope_gate = ScopeGate(
            allowed_cidrs=self.config.scope.allowed_cidrs,
            allowed_ports=self.config.scope.allowed_ports
        )
        self.state = SharedState(scope_gate=self.scope_gate)
        self.reporter = ReportGenerator(
            state=self.state,
            project_name=self.config.project_name,
            tier=self.config.tier,
            allowed_cidrs=self.config.scope.allowed_cidrs
        )
        set_state_reference(self.state, self.reporter)

        self._agent_registry: Dict[str, BaseAgent] = {}
        self._server_thread: Optional[threading.Thread] = None
        self._bootstrap_agents()

    def _bootstrap_agents(self) -> None:
        """Dynamically instantiate configured agents based on config.yaml (Bonus B-4)."""
        from cyberforge.agents.web_agent import WebAgent
        from cyberforge.agents.network_agent import NetworkDiscoveryAgent
        from cyberforge.agents.verification_agent import VerificationAgent
        from cyberforge.agents.service_auth_agent import ServiceAuthAgent

        for agent_cfg in self.config.agents:
            if not agent_cfg.enabled:
                continue

            if agent_cfg.name == "network_discovery":
                agent = NetworkDiscoveryAgent(agent_cfg, self.state, self.scope_gate)
                self.register_agent(agent)
            elif agent_cfg.name == "web_agent":
                agent = WebAgent(agent_cfg, self.state, self.scope_gate)
                self.register_agent(agent)
            elif agent_cfg.name == "verification_agent":
                agent = VerificationAgent(agent_cfg, self.state, self.scope_gate)
                self.register_agent(agent)
            elif agent_cfg.name == "service_auth_agent":
                agent = ServiceAuthAgent(agent_cfg, self.state, self.scope_gate)
                self.register_agent(agent)

    def register_agent(self, agent: BaseAgent) -> None:
        """Register an agent instance into the coordinator."""
        self._agent_registry[agent.name] = agent
        logger.info(f"Registered agent: {agent.name} (Surface: {agent.surface})")

    def start_api_server(self) -> None:
        """Starts the FastAPI status/reporting server in a background thread."""
        def run_server():
            uvicorn.run(
                app,
                host=self.config.reporting.api_host,
                port=self.config.reporting.api_port,
                log_level="warning"
            )

        self._server_thread = threading.Thread(target=run_server, daemon=True)
        self._server_thread.start()
        logger.info(f"API Server listening on http://{self.config.reporting.api_host}:{self.config.reporting.api_port}")

    def load_latest_report(self) -> bool:
        """
        Loads findings, targets, and attack path from the latest saved JSON report into state.
        Safeguard: strictly matches report's scope against currently configured scope.
        """
        import glob
        import json
        import os
        from cyberforge.core.models import TargetHost, Finding, AttackPathStep

        export_dir = self.config.reporting.export_dir
        json_files = glob.glob(os.path.join(export_dir, "assessment_*.json"))
        if not json_files:
            logger.warning(f"No previous assessment reports found in {export_dir}")
            return False

        current_scope_set = set(self.config.scope.allowed_cidrs)
        matching_files = []

        # Sort candidate files newest to oldest
        sorted_files = sorted(json_files, key=os.path.getmtime, reverse=True)
        for filepath in sorted_files:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Check scope match in scope_summary or attack path
                report_scope = data.get("scope_summary", {}).get("allowed_cidrs", [])
                if not report_scope and data.get("attack_path"):
                    # Fallback check from first attack path step details
                    first_step_details = data["attack_path"][0].get("details", "")
                    for cidr in self.config.scope.allowed_cidrs:
                        if cidr in first_step_details:
                            report_scope.append(cidr)

                if set(report_scope) == current_scope_set or any(cidr in str(report_scope) for cidr in current_scope_set):
                    matching_files.append((filepath, data))
                    break  # Found newest matching report
            except Exception as e:
                logger.debug(f"Could not inspect report {filepath}: {e}")

        if not matching_files:
            logger.warning(
                f"No previous assessment reports matching current scope {self.config.scope.allowed_cidrs} found in {export_dir}"
            )
            return False

        latest_file, data = matching_files[0]
        try:
            with self.state._lock:
                for h_dict in data.get("hosts", []):
                    host = TargetHost.model_validate(h_dict)
                    if host.ports and "network" not in host.tested_surfaces:
                        host.tested_surfaces.insert(0, "network")
                    self.state._hosts[host.host_id] = host

                for f_dict in data.get("findings", []):
                    finding = Finding.model_validate(f_dict)
                    self.state._findings[finding.id] = finding

                for s_dict in data.get("attack_path", []):
                    step = AttackPathStep.model_validate(s_dict)
                    self.state._attack_path.append(step)

            logger.info(
                f"Loaded {len(self.state._hosts)} hosts and {len(self.state._findings)} findings from scope-verified report {latest_file}"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to load verified report {latest_file}: {e}")
            return False

    def run_pipeline(self) -> None:
        """
        Orchestrates the autonomous multi-agent execution loop.
        1. Pre-engagement: Enforce scope & audit.
        2. Intelligence Gathering: Network discovery.
        3. Tri-surface Dispatch: Web and Binary analysis on discovered surfaces.
        4. Verification Pass: Validate flagged findings.
        5. Reporting: Save final outputs.
        """
        logger.info("=== Starting CyberForge Multi-Agent Pipeline ===")
        self.state.log_step(
            host_ip=self.config.scope.allowed_cidrs[0] if self.config.scope.allowed_cidrs else "0.0.0.0",
            phase=PTESPhase.PRE_ENGAGEMENT,
            surface=SurfaceType.NETWORK,
            action_taken="Scope verification and initialization",
            details=f"Scope locked to: {self.config.scope.allowed_cidrs}"
        )

        self.start_api_server()

        # Step 1: Run network discovery if registered
        network_agent = self._agent_registry.get("network_discovery")
        if network_agent:
            logger.info("Executing Network Discovery Agent...")
            # Discovering within allowed scope
            for cidr in self.config.scope.allowed_cidrs:
                dummy_target = TargetHost(host_id="network-init", ip=cidr)
                network_agent.execute(dummy_target)

        # Step 2: Surface dispatch loop (Web Agent - Intelligence Gathering & App Analysis)
        hosts = self.state.list_hosts()
        logger.info(f"Discovered {len(hosts)} target hosts. Dispatching surface agents...")

        for host in hosts:
            has_web = any(
                p.port in (80, 443, 8080, 8000, 8443) or "http" in p.service.lower()
                for p in host.ports
            )
            web_agent = self._agent_registry.get("web_agent")
            if has_web and web_agent and not self.state.is_surface_tested(host.host_id, "web"):
                if self.state.claim_host("web_agent", host.host_id):
                    logger.info(f"Handing off host {host.ip} to Web Agent...")
                    web_agent.execute(host)
                    self.state.mark_surface_tested(host.host_id, "web")

            # Check for binary services or analysis
            binary_agent = self._agent_registry.get("binary_agent")
            if binary_agent and not self.state.is_surface_tested(host.host_id, "binary"):
                if self.state.claim_host("binary_agent", host.host_id):
                    logger.info(f"Handing off host {host.ip} to Binary Agent...")
                    binary_agent.execute(host)
                    self.state.mark_surface_tested(host.host_id, "binary")

        # Step 3: Service authentication probe (FR-3 / FR-4 Collaborative Handoff)
        # Consumes intelligence (passkeys, exposed artifacts) uncovered by Web Agent
        hosts = self.state.list_hosts()
        service_auth_agent = self._agent_registry.get("service_auth_agent")
        if service_auth_agent:
            logger.info(f"Dispatching Service Auth Agent against {len(hosts)} hosts with blackboard intel...")
            for host in hosts:
                if not self.state.is_surface_tested(host.host_id, "service_auth"):
                    service_auth_agent.execute(host)

        # Step 4: Run verification engine if registered (FR-6)
        verifier = self._agent_registry.get("verification_agent")
        if verifier:
            logger.info("Dispatching Verification Engine (FR-6) for unverified findings...")
            for host in hosts:
                verifier.execute(host)

        # Step 5: Final Reporting (FR-7)
        logger.info("Generating assessment reports...")
        self.state.log_step(
            host_ip="localhost",
            phase=PTESPhase.REPORTING,
            surface=SurfaceType.NETWORK,
            action_taken="Consolidated assessment report generated"
        )
        saved = self.reporter.save_reports(self.config.reporting.export_dir)
        logger.info(f"Reports generated: {saved['markdown']} and {saved['json']}")
        logger.info("=== CyberForge Assessment Finished Successfully ===")

