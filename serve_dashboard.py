"""
CyberForge Dashboard Server
Loads the latest assessment findings and starts the live web UI on http://localhost:8000
"""

import os
import glob
import json
import webbrowser
import uvicorn
from cyberforge.core.state import SharedState
from cyberforge.core.models import PortService
from cyberforge.reporting.generator import ReportGenerator
from cyberforge.api.server import app, set_state_reference


def main():
    # Find latest assessment report
    reports = sorted(glob.glob("reports/assessment_*.json"))
    if not reports:
        print("[!] No assessment reports found in ./reports/")
        return

    latest_report = reports[-1]
    print(f"[*] Loading assessment data from: {latest_report}")

    with open(latest_report, "r", encoding="utf-8") as f:
        data = json.load(f)

    state = SharedState()

    # Load hosts
    for h in data.get("hosts", []):
        ports = [
            PortService(
                port=p["port"],
                protocol=p.get("protocol", "tcp"),
                service=p.get("service", "unknown"),
                version=p.get("version"),
            )
            for p in h.get("ports", [])
        ]
        registered = state.register_or_update_host(
            ip=h["ip"],
            ports=ports,
            mac_address=h.get("mac_address"),
            mac_vendor=h.get("mac_vendor"),
        )
        for s in h.get("tested_surfaces", []):
            state.mark_surface_tested(registered.host_id, s)

    # Load findings and recon notes
    raw_findings = data.get("findings", []) + data.get("recon_notes", [])
    seen_ids = set()
    for f in raw_findings:
        if f["id"] in seen_ids:
            continue
        seen_ids.add(f["id"])
        state.add_finding(
            host_id=f["host_id"],
            host_ip=f["host_ip"],
            port=f.get("port"),
            surface=f["surface"],
            ptes_phase=f["ptes_phase"],
            finding_type=f["finding_type"],
            title=f["title"],
            description=f["description"],
            evidence=f["evidence"],
            verified=f.get("verified", False),
            status=f.get("status", "FLAGGED"),
            remediation=f.get("remediation", ""),
            flag=f.get("flag"),
        )

    # Load attack path
    for p in data.get("attack_path", []):
        state.log_step(
            host_ip=p["host_ip"],
            phase=p["phase"],
            surface=p["surface"],
            action_taken=p["action_taken"],
            finding_ref=p.get("finding_ref"),
            details=p.get("details"),
        )

    allowed_cidrs = data.get("scope_cidrs") or data.get("scope_summary", {}).get("allowed_cidrs", ["192.168.60.139/32"])
    reporter = ReportGenerator(
        state,
        project_name="LinkRunner Assessment",
        tier=data.get("tier", "recon"),
        allowed_cidrs=allowed_cidrs,
    )

    set_state_reference(state, reporter)

    print("\n" + "=" * 60)
    print("  LinkRunner Web Dashboard Running at: http://localhost:8000")
    print("  Press Ctrl+C to stop the server")
    print("=" * 60 + "\n")

    # Automatically open in browser
    try:
        webbrowser.open("http://localhost:8000")
    except Exception:
        pass

    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()

