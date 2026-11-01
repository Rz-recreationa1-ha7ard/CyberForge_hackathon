import os
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from cyberforge.core.state import SharedState
from cyberforge.core.models import Finding, TargetHost, AttackPathStep, FindingStatus, PTESPhase


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

# Maps finding_type -> (severity_label, rank)
# rank 0 = most severe (critical), higher numbers = less severe.
# Anything not in this table falls back to rank 4 (low).
_FINDING_SEVERITY: Dict[str, Tuple[str, int]] = {
    # Critical -- direct unauthenticated/default access to a service
    "default_database_credential": ("critical", 0),
    "default_telnet_credential":   ("critical", 0),
    "unauthenticated_redis":       ("critical", 0),
    "smb_null_session":            ("critical", 0),
    "gamezone_auth_arbitrary_read":("critical", 0),
    # High -- form bypass / active exploit proven
    "sql_injection_auth_bypass":   ("high", 1),
    "flag_captured":               ("high", 1),
    "ip_spoofing_bypass":          ("high", 1),
    # Medium -- confirmed weakness, no direct access yet
    "sql_injection_error":         ("medium", 2),
    "exposed_path":                ("medium", 2),
    "reflected_input":             ("medium", 2),
    # Low -- defence-in-depth gaps, no direct impact
    "missing_header":              ("low", 3),
    "discovered_form":             ("low", 4),
    "recon_note":                  ("low", 4),
}

# Human-readable one-line templates for the narrative.
# Placeholders: {host} = IP, {port} = port number, {detail} = extra context.
_NARRATIVE_TEMPLATES: Dict[str, str] = {
    "default_database_credential": (
        "Default credentials on the database service at `{host}:{port}` allow any "
        "network attacker to authenticate directly without knowing a valid password."
    ),
    "default_telnet_credential": (
        "Well-known default credentials give interactive shell access via Telnet at "
        "`{host}:{port}`, with all traffic transmitted in cleartext."
    ),
    "unauthenticated_redis": (
        "Redis at `{host}:{port}` accepts connections with no password, exposing the "
        "entire cache and potentially enabling arbitrary command execution."
    ),
    "smb_null_session": (
        "An anonymous SMB session is accepted at `{host}:{port}`, allowing share "
        "enumeration and further network reconnaissance without credentials."
    ),
    "gamezone_auth_arbitrary_read": (
        "Reverse engineering the proprietary 'keykeeper' binary recovered the passkey "
        "to authenticate to the Game Zone service at `{host}:{port}`, enabling arbitrary "
        "PID resource request and exfiltration of the planted CTF flag."
    ),
    "sql_injection_auth_bypass": (
        "A SQL injection tautology bypasses the login form at `{host}:{port}`, "
        "granting authenticated access to the application without valid credentials."
    ),
    "ip_spoofing_bypass": (
        "Injecting an internal gateway IP into the 'X-Forwarded-For' header bypassed "
        "the reverse proxy access controls at `{host}:{port}`, disclosing confidential internal wiki documentation."
    ),
    "flag_captured": (
        "A planted CTF flag was recovered from `{host}:{port}` ({detail}), "
        "confirming attacker read access to web application responses."
    ),
    "sql_injection_error": (
        "The web form at `{host}:{port}` leaks raw database error messages, "
        "disclosing the SQL structure and aiding further injection attempts."
    ),
    "exposed_path": (
        "A sensitive path is accessible without authentication at `{host}:{port}` "
        "({detail}), potentially exposing configuration or backup data."
    ),
    "reflected_input": (
        "User-supplied input is reflected unescaped in the response at "
        "`{host}:{port}`, a prerequisite for cross-site scripting attacks."
    ),
}


def _severity_rank(finding_type: str) -> Tuple[str, int]:
    """Return (label, rank) for a finding type. Lower rank = more severe."""
    return _FINDING_SEVERITY.get(finding_type, ("low", 4))


class ReportGenerator:
    """
    Produces consolidated PTES-compliant penetration test reports (FR-7)
    and maps the discovered attack path, evidence, and remediation (B-3).
    """

    def __init__(self, state: SharedState, project_name: str = "LinkRunner Assessment", tier: str = "recon", allowed_cidrs: Optional[List[str]] = None):
        self.state = state
        self.project_name = project_name
        self.tier = tier
        self.allowed_cidrs = allowed_cidrs or []

    # ------------------------------------------------------------------
    # Synthesised Attack Narrative (B-3 / Section 4)
    # ------------------------------------------------------------------

    def _build_attack_narrative(
        self,
        findings: List[Dict[str, Any]],
        max_steps: int = 8,
    ) -> List[Dict[str, Any]]:
        """
        Builds a prioritised, synthesised attack narrative from confirmed findings.

        Algorithm:
        1. Consider only *confirmed/verified* findings that are not pure recon
           observations (discovered_form / recon_note).
        2. For each host, keep only its single most-severe confirmed finding.
        3. Discard hosts whose best finding is ranked "low" (missing headers, etc.)
           so the narrative stays focused on real impact.
        4. Sort hosts by their best-finding rank (critical first).
        5. Take the top `max_steps` and build a one-sentence narrative per step.

        Returns a list of dicts with keys:
            step, host_ip, port, finding_type, severity, narrative_sentence
        """
        RECON_TYPES = {"discovered_form", "recon_note"}

        # --- Step 1: filter to confirmed, non-recon findings ---
        actionable = [
            f for f in findings
            if f.get("finding_type") not in RECON_TYPES
            and (f.get("status") == FindingStatus.CONFIRMED.value or f.get("verified"))
        ]

        # --- Step 2: best finding per host ---
        best_per_host: Dict[str, Dict[str, Any]] = {}
        for f in actionable:
            host_ip = f["host_ip"]
            _, rank = _severity_rank(f["finding_type"])
            if host_ip not in best_per_host:
                best_per_host[host_ip] = f
            else:
                _, existing_rank = _severity_rank(best_per_host[host_ip]["finding_type"])
                if rank < existing_rank:
                    best_per_host[host_ip] = f

        # --- Step 3: drop low-severity hosts ---
        significant = {
            ip: f for ip, f in best_per_host.items()
            if _severity_rank(f["finding_type"])[1] <= 2  # critical=0, high=1, medium=2
        }

        # --- Step 4: sort by severity rank (most severe first) ---
        ordered = sorted(
            significant.values(),
            key=lambda f: _severity_rank(f["finding_type"])[1],
        )

        # --- Step 5: build narrative sentences ---
        narrative: List[Dict[str, Any]] = []
        for idx, f in enumerate(ordered[:max_steps], start=1):
            ftype = f["finding_type"]
            severity_label, _ = _severity_rank(ftype)
            template = _NARRATIVE_TEMPLATES.get(ftype)

            # Extract a short detail string (flag value, path, etc.)
            detail = ""
            if ftype == "flag_captured" and f.get("flag"):
                detail = f.get("flag", "")
            elif ftype in ("exposed_path", "sql_injection_error", "reflected_input"):
                # Pull the path/endpoint from the title if present
                title = f.get("title", "")
                if ": " in title:
                    detail = title.split(": ", 1)[-1]

            if template:
                sentence = template.format(
                    host=f["host_ip"],
                    port=f.get("port") or "N/A",
                    detail=detail,
                )
            else:
                sentence = (
                    f"A {severity_label}-severity issue ({ftype.replace('_', ' ')}) "
                    f"was confirmed at `{f['host_ip']}:{f.get('port') or 'N/A'}`."
                )

            narrative.append({
                "step": idx,
                "host_ip": f["host_ip"],
                "port": f.get("port"),
                "finding_type": ftype,
                "severity": severity_label,
                "finding_id": f["id"],
                "narrative_sentence": sentence,
            })

        return narrative

    def generate_json_data(self) -> Dict[str, Any]:
        hosts = [h.model_dump() for h in self.state.list_hosts()]
        findings = [f.model_dump(mode="json") for f in self.state.get_findings()]
        attack_path = [p.model_dump(mode="json") for p in self.state.get_attack_path()]

        # Separate true vulnerabilities from reconnaissance observations (forms/endpoints)
        recon_types = ("discovered_form", "recon_note")
        vuln_findings = [f for f in findings if f.get("finding_type") not in recon_types]
        recon_notes = [f for f in findings if f.get("finding_type") in recon_types]

        confirmed_vuln_count = sum(
            1 for f in vuln_findings
            if f.get("status") == FindingStatus.CONFIRMED.value or f.get("verified")
        )
        flagged_vuln_count = len(vuln_findings) - confirmed_vuln_count

        # Build synthesised attack narrative
        attack_narrative = self._build_attack_narrative(findings)

        return {
            "project_name": self.project_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tier": self.tier,
            "scope_summary": {
                "allowed_cidrs": self.allowed_cidrs
            },
            "summary": {
                "total_hosts": len(hosts),
                "total_vulnerabilities": len(vuln_findings),
                "confirmed_vulnerabilities": confirmed_vuln_count,
                "unverified_vulnerabilities": flagged_vuln_count,
                "total_findings": len(vuln_findings),
                "confirmed_findings": confirmed_vuln_count,
                "unverified_findings": flagged_vuln_count,
                "recon_items": len(recon_notes),
                "attack_path_steps": len(attack_path),
                "attack_narrative_steps": len(attack_narrative),
            },
            "hosts": hosts,
            "vulnerabilities": vuln_findings,
            "recon_notes": recon_notes,
            "findings": vuln_findings,
            "attack_path": attack_path,
            "attack_narrative": attack_narrative,
        }

    def generate_markdown_report(self) -> str:
        data = self.generate_json_data()
        summary = data["summary"]

        md = []
        md.append(f"# {self.project_name} -- Security Assessment Report\n")
        md.append(f"**Date:** {data['generated_at']}  ")
        md.append(f"**Evaluation Tier:** {self.tier.capitalize()}  ")
        if self.allowed_cidrs:
            md.append(f"**Scope Summary:** `{', '.join(self.allowed_cidrs)}`  ")
        md.append(f"**Methodology:** Penetration Testing Execution Standard (PTES)\n")
        md.append("---\n")

        # Executive Summary
        md.append("## 1. Executive Summary\n")
        md.append(f"During the autonomous assessment, the engine identified **{summary['total_hosts']} host(s)**, ")
        md.append(f"cataloged **{summary['recon_items']} reconnaissance asset(s)** (input forms & endpoints), ")
        md.append(f"and uncovered a total of **{summary['total_vulnerabilities']} vulnerability finding(s)** ")
        md.append(f"(**{summary['confirmed_vulnerabilities']} verified/confirmed**, {summary['unverified_vulnerabilities']} flagged for review).\n")

        # Discovered Target Inventory
        md.append("## 2. Discovered Target Inventory (Intelligence Gathering)\n")
        md.append("| Host ID | IP Address | MAC Address | Hardware Vendor | Hostname | Open Ports & Services | Tested Surfaces |\n")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for h in data["hosts"]:
            ports_str = ", ".join([f"{p['port']}/{p['protocol']} ({p['service']})" for p in h.get("ports", [])]) or "None"
            surfaces = list(h.get("tested_surfaces", []))
            if h.get("ports") and "network" not in surfaces:
                surfaces.insert(0, "network")
            surfaces_str = ", ".join(surfaces) if surfaces else "None"
            mac_str = f"`{h['mac_address']}`" if h.get("mac_address") else "Unknown"
            vendor_str = h.get("mac_vendor") or "Unknown"
            md.append(f"| `{h['host_id']}` | `{h['ip']}` | {mac_str} | {vendor_str} | {h.get('hostname') or 'N/A'} | {ports_str} | {surfaces_str} |\n")

        # Reconnaissance Notes (Forms & Inputs - Separated from Vulnerabilities)
        md.append("\n## 3. Reconnaissance Notes & Discovered Forms (Intelligence Gathering)\n")
        if not data["recon_notes"]:
            md.append("*No web input forms cataloged.*\n")
        else:
            md.append("| Host IP | Form Type | Action Endpoint | Method | Form Fields |\n")
            md.append("| :--- | :--- | :--- | :--- | :--- |\n")
            for r in data["recon_notes"]:
                evidence_str = r.get("evidence", "")
                action_part = ""
                fields_part = ""
                if "Form Action: " in evidence_str:
                    try:
                        action_part = evidence_str.split("Form Action: ")[1].split(", Method: ")[0]
                        fields_part = evidence_str.split("Fields: ")[1]
                    except Exception:
                        action_part = r.get("description", "")
                md.append(f"| `{r['host_ip']}` | {r['title']} | `{action_part or 'N/A'}` | `{r.get('method', 'POST')}` | `{fields_part[:60]}` |\n")

        # Attack Path Narrative (synthesised, priority-ordered)
        md.append("\n## 4. Synthesised Attack Path Narrative\n")
        narrative = data.get("attack_narrative", [])
        if not narrative:
            md.append(
                "*No medium-or-above confirmed findings were recorded -- "
                "no attack narrative could be constructed.*\n"
            )
        else:
            severity_badge = {
                "critical": "[CRITICAL]",
                "high":     "[HIGH]",
                "medium":   "[MEDIUM]",
            }
            md.append(
                "> The steps below represent the highest-impact confirmed findings, "
                "ordered by severity. Each describes the real-world impact an attacker "
                "could achieve using that weakness.\n"
            )
            for step in narrative:
                badge = severity_badge.get(step["severity"], "[UNKNOWN]")
                finding_ref = step.get("finding_id", "")
                md.append(
                    f"**Step {step['step']}** [{badge}]  \n"
                    f"{step['narrative_sentence']}  \n"
                    f"*(Finding ID: `{finding_ref}` -- see Section 5 for full evidence)*\n"
                )

        # Detailed Vulnerability Findings (Strictly vulnerabilities only)
        md.append("\n## 5. Detailed Vulnerability Findings\n")
        if not data["vulnerabilities"]:
            md.append("*No vulnerabilities recorded during this run.*\n")
        else:
            for idx, f in enumerate(data["vulnerabilities"], start=1):
                status_badge = "[CONFIRMED]" if f.get("status") == "CONFIRMED" or f.get("verified") else "[FLAGGED]"
                md.append(f"### 5.{idx}. {f['title']} [{status_badge}]\n")
                md.append(f"- **Finding ID:** `{f['id']}`")
                md.append(f"- **Host:** `{f['host_ip']}` (Port: `{f.get('port') or 'N/A'}`)")
                md.append(f"- **Surface:** `{f['surface']}`")
                md.append(f"- **PTES Phase:** `{f['ptes_phase']}`")
                md.append(f"- **Verification Status:** `{'Verified' if f.get('verified') else 'Unverified'}`\n")
                md.append(f"**Description:**  \n{f['description']}\n")
                md.append(f"**Evidence:**  \n```\n{f['evidence']}\n```\n")
                if f.get("remediation"):
                    md.append(f"**Plain-English Remediation (B-3):**  \n> {f['remediation']}\n")
                if f.get("flag"):
                    md.append(f"**Captured Flag (B-1):** `{f['flag']}`\n")
                md.append("---\n")

        return "\n".join(md)

    def save_reports(self, output_dir: str = "./reports") -> Dict[str, str]:
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        json_path = os.path.join(output_dir, f"assessment_{timestamp}.json")
        md_path = os.path.join(output_dir, f"assessment_{timestamp}.md")

        data = self.generate_json_data()
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        md_content = self.generate_markdown_report()
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        return {"json": json_path, "markdown": md_path}
