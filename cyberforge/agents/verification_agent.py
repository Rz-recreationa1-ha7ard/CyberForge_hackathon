import re
import urllib.request
import urllib.parse
import uuid
import logging
from typing import Dict, Any, Optional

from cyberforge.agents.base import BaseAgent
from cyberforge.core.models import TargetHost, Finding, FindingStatus, PTESPhase, SurfaceType
from cyberforge.core.config import AgentConfig
from cyberforge.core.state import SharedState
from cyberforge.core.scope_gate import ScopeGate


class VerificationAgent(BaseAgent):
    """
    Finding Verification Engine (FR-6).
    Verifies flagged weaknesses, validates authenticity, and filters out false alarms
    (such as soft-404 responses) to achieve the 'Great' benchmark (100% verified, <10% false alarms).
    """

    def __init__(self, config: AgentConfig, state: SharedState, scope_gate: ScopeGate):
        super().__init__(config, state, scope_gate)
        self.timeout = self.config.parameters.get("timeout_seconds", 3)

    def _fetch(self, url: str) -> Optional[tuple[int, str]]:
        parsed = urllib.parse.urlparse(url)
        host_ip = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if not self.is_target_in_scope(host_ip, port):
            return None

        req = urllib.request.Request(url, headers={"User-Agent": "CyberForge-Verifier/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return resp.status, body
        except Exception:
            return None

    def execute(self, host: TargetHost, **kwargs) -> None:
        """
        Runs verification passes across all unconfirmed findings for the host (FR-6).
        """
        findings = self.state.get_findings(host_id=host.host_id)
        unverified_findings = [f for f in findings if not f.verified or f.status == FindingStatus.FLAGGED]

        if not unverified_findings:
            return

        self.logger.info(f"Running verification engine on {len(unverified_findings)} flagged findings for {host.ip}...")

        # Canary probe for Soft-404 detection
        canary_url = f"http://{host.ip}:{host.ports[0].port if host.ports else 80}/cf_canary_notfound_{uuid.uuid4().hex[:8]}"
        canary_res = self._fetch(canary_url)
        canary_code = canary_res[0] if canary_res else 404
        canary_body = canary_res[1] if canary_res else ""

        for finding in unverified_findings:
            if finding.finding_type == "exposed_path":
                self._verify_exposed_path(finding, canary_code, canary_body)

    @staticmethod
    def _detect_sensitive_content(target_url: str, body: str) -> Optional[str]:
        """
        Determines whether actual sensitive data/content was read from the response,
        warranting the PTES Exploitation phase label (vs merely Vulnerability Analysis).
        """
        if not body:
            return None

        lower_body = body.lower()
        lower_url = target_url.lower()

        # Check for planted CTF flags
        flag_match = re.search(r"(flag\{[^\s\}]+\}|CTF\{[^\s\}]+\})", body, re.IGNORECASE)
        if flag_match:
            return f"Planted CTF flag read from endpoint: {flag_match.group(1)}"

        # 1. Git repository config (.git/config)
        if ".git" in lower_url:
            if "[core]" in lower_body or "repositoryformatversion" in lower_body or "bare =" in lower_body:
                return "Exposed Git repository configuration ([core] section verified)"

        # 2. Environment files (.env)
        if ".env" in lower_url:
            env_keywords = ["db_password", "secret_key", "api_key", "app_key", "database_url", "aws_secret", "jwt_secret", "password", "secret"]
            if any(kw in lower_body for kw in env_keywords) or re.search(r"^[a-zA-Z0-9_]+\s*=\s*\S+", body, re.MULTILINE):
                return "Exposed environment configuration with key-value parameters"

        # 3. AWS credentials (.aws/credentials)
        if ".aws" in lower_url or "credentials" in lower_url:
            if "aws_access_key_id" in lower_body or "aws_secret_access_key" in lower_body or "[default]" in lower_body:
                return "Exposed AWS credentials file ([default] profile or access keys)"

        # 4. Configuration backups (config.php.bak, wp-config.php.bak, admin/config)
        if any(p in lower_url for p in ["config.php", "wp-config", "admin/config", ".bak"]):
            php_indicators = ["<?php", "define(", "db_password", "db_name", "db_user", "$db[", "$config"]
            if any(ind in lower_body for ind in php_indicators):
                return "Exposed application configuration file containing source directives/credentials"

        # 5. Apache server-status (/server-status)
        if "server-status" in lower_url:
            if "apache server status" in lower_body or "server uptime" in lower_body or "total accesses:" in lower_body:
                return "Exposed Apache server-status metrics and client connections"

        # 6. Backup directories (/backup)
        if "/backup" in lower_url:
            backup_indicators = ["index of /backup", ".tar", ".zip", ".sql", ".bak", "parent directory"]
            if any(ind in lower_body for ind in backup_indicators):
                return "Exposed directory listing or archive index in backup path"

        return None

    def _verify_exposed_path(self, finding: Finding, canary_code: int, canary_body: str) -> None:
        """
        Proves whether an exposed path is genuine or a soft-404 false alarm.
        Classifies PTES phase based on whether sensitive content was actually read:
        - Real sensitive content read (credentials, secrets, config, source): EXPLOITATION
        - Accessible path returning 200 without sensitive content leak: VULNERABILITY_ANALYSIS
        """
        # Extract target URL from evidence
        lines = finding.evidence.split("\n")
        url_line = next((l for l in lines if l.startswith("URL: ")), "")
        target_url = url_line.replace("URL: ", "").split(" returned")[0].strip() if url_line else ""

        if not target_url:
            return

        probe_res = self._fetch(target_url)
        if not probe_res:
            return

        code, body = probe_res

        # False alarm check: If server returns HTTP 200 for nonexistent canaries with similar body
        is_soft_404 = False
        if canary_code == 200 and abs(len(body) - len(canary_body)) < 100:
            is_soft_404 = True

        # Check for explicit error strings in response body
        error_keywords = ["404 not found", "page not found", "does not exist", "error 404", "cannot be found"]
        if any(kw in body.lower() for kw in error_keywords):
            is_soft_404 = True

        if is_soft_404:
            self.logger.info(f"FALSE ALARM FILTERED: Path {target_url} identified as soft-404.")
            finding.status = FindingStatus.FLAGGED
            finding.evidence += "\n[VERIFIER]: Soft-404 false alarm detected. Target omitted from confirmed findings."
        else:
            sensitive_desc = self._detect_sensitive_content(target_url, body)
            if sensitive_desc:
                # Real sensitive content actually read -> EXPLOITATION phase
                self.logger.info(f"SENSITIVE DATA EXPOSED (EXPLOITATION): {target_url} - {sensitive_desc}")
                self.state.verify_finding(
                    finding_id=finding.id,
                    verified=True,
                    extra_evidence=(
                        f"Active verification confirmed HTTP 200 with authentic distinct content (length: {len(body)} bytes).\n"
                        f"[SENSITIVE DATA EXPOSED]: {sensitive_desc}"
                    ),
                    ptes_phase=PTESPhase.EXPLOITATION
                )
                self.log_ptes_action(
                    host_ip=finding.host_ip,
                    phase=PTESPhase.EXPLOITATION,
                    action=f"Sensitive Data Read: {finding.title}",
                    details=f"{sensitive_desc} from {target_url}"
                )
            else:
                # Open path verified, but no sensitive content read -> VULNERABILITY_ANALYSIS phase
                self.logger.info(f"EXPOSED PATH CONFIRMED (VULNERABILITY ANALYSIS): {target_url}")
                self.state.verify_finding(
                    finding_id=finding.id,
                    verified=True,
                    extra_evidence=(
                        f"Active verification confirmed HTTP 200 with authentic distinct content (length: {len(body)} bytes). "
                        f"Endpoint is accessible without authentication (no direct secrets/credentials read from body)."
                    ),
                    ptes_phase=PTESPhase.VULNERABILITY_ANALYSIS
                )
                self.log_ptes_action(
                    host_ip=finding.host_ip,
                    phase=PTESPhase.VULNERABILITY_ANALYSIS,
                    action=f"Weakness Confirmed: {finding.title}",
                    details=f"Path {target_url} returned HTTP 200 without authentication"
                )

