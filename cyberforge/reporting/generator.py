import os
import json
from typing import Dict, Any, List
from datetime import datetime, timezone
from cyberforge.core.state import SharedState
from cyberforge.core.models import Finding, TargetHost, AttackPathStep, FindingStatus


class ReportGenerator:
    """
    Produces consolidated PTES-compliant penetration test reports (FR-7)
    and maps the discovered attack path, evidence, and remediation (B-3).
    """

    def __init__(self, state: SharedState, project_name: str = "CyberForge Assessment", tier: str = "recon"):
        self.state = state
        self.project_name = project_name
        self.tier = tier

    def generate_json_data(self) -> Dict[str, Any]:
        hosts = [h.model_dump() for h in self.state.list_hosts()]
        findings = [f.model_dump(mode="json") for f in self.state.get_findings()]
        attack_path = [p.model_dump(mode="json") for p in self.state.get_attack_path()]

        confirmed_count = sum(1 for f in findings if f.get("status") == FindingStatus.CONFIRMED.value or f.get("verified"))
        flagged_count = len(findings) - confirmed_count

        return {
            "project_name": self.project_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tier": self.tier,
            "summary": {
                "total_hosts": len(hosts),
                "total_findings": len(findings),
                "confirmed_findings": confirmed_count,
                "unverified_findings": flagged_count,
                "attack_path_steps": len(attack_path),
            },
            "hosts": hosts,
            "findings": findings,
            "attack_path": attack_path,
        }

    def generate_markdown_report(self) -> str:
        data = self.generate_json_data()
        summary = data["summary"]

        md = []
        md.append(f"# {self.project_name} — Security Assessment Report\n")
        md.append(f"**Date:** {data['generated_at']}  ")
        md.append(f"**Evaluation Tier:** {self.tier.capitalize()}  ")
        md.append(f"**Methodology:** Penetration Testing Execution Standard (PTES)\n")
        md.append("---\n")

        # Executive Summary
        md.append("## 1. Executive Summary\n")
        md.append(f"During the autonomous assessment, the engine identified **{summary['total_hosts']} host(s)** ")
        md.append(f"and uncovered a total of **{summary['total_findings']} finding(s)** ")
        md.append(f"(**{summary['confirmed_findings']} verified/confirmed**, {summary['unverified_findings']} flagged for review).\n")

        # Discovered Target Inventory
        md.append("## 2. Discovered Target Inventory (Intelligence Gathering)\n")
        md.append("| Host ID | IP Address | Hostname | Open Ports & Services | Tested Surfaces |\n")
        md.append("| :--- | :--- | :--- | :--- | :--- |\n")
        for h in data["hosts"]:
            ports_str = ", ".join([f"{p['port']}/{p['protocol']} ({p['service']})" for p in h.get("ports", [])]) or "None"
            surfaces_str = ", ".join(h.get("tested_surfaces", [])) or "None"
            md.append(f"| `{h['host_id']}` | `{h['ip']}` | {h.get('hostname') or 'N/A'} | {ports_str} | {surfaces_str} |\n")

        # Attack Path & PTES Timeline
        md.append("\n## 3. Attack Path & PTES Execution Timeline\n")
        if data["attack_path"]:
            md.append("| Step | Target IP | PTES Phase | Surface | Action Taken | Details |\n")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
            for step in data["attack_path"]:
                md.append(f"| {step['step_number']} | `{step['host_ip']}` | {step['phase']} | {step['surface']} | {step['action_taken']} | {step.get('details') or ''} |\n")
        else:
            md.append("*No attack path steps recorded.*\n")

        # Detailed Findings
        md.append("\n## 4. Detailed Vulnerability Findings\n")
        if not data["findings"]:
            md.append("*No vulnerabilities recorded during this run.*\n")
        else:
            for idx, f in enumerate(data["findings"], start=1):
                status_badge = "🔴 CONFIRMED" if f.get("status") == "CONFIRMED" or f.get("verified") else "🟡 FLAGGED"
                md.append(f"### 4.{idx}. {f['title']} [{status_badge}]\n")
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
