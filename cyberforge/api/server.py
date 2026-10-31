from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from typing import List, Dict, Any, Optional
from cyberforge.core.state import SharedState
from cyberforge.reporting.generator import ReportGenerator

app = FastAPI(
    title="CyberForge Autonomous PTES Engine API",
    description="Unified API for querying discovered targets, verified findings, and attack paths.",
    version="1.0.0"
)

# Reference to the shared state singleton (set during engine bootstrap)
engine_state: Optional[SharedState] = None
report_gen: Optional[ReportGenerator] = None


def set_state_reference(state: SharedState, reporter: ReportGenerator) -> None:
    global engine_state, report_gen
    engine_state = state
    report_gen = reporter


@app.get("/", response_class=HTMLResponse)
def index_dashboard():
    """Simple status dashboard (FR-7 & B-5 preview)"""
    if not engine_state:
        return "<h1>CyberForge Engine Initializing...</h1>"

    hosts = engine_state.list_hosts()
    findings = engine_state.get_findings()
    steps = engine_state.get_attack_path()

    confirmed = sum(1 for f in findings if f.status == "CONFIRMED" or f.verified)

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberForge PTES Engine Dashboard</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; background: #0f172a; color: #f8fafc; }}
            .card {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }}
            .grid {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; }}
            .metric {{ flex: 1; background: #1e293b; padding: 1rem; border-radius: 8px; text-align: center; border: 1px solid #334155; }}
            .metric h2 {{ margin: 0; font-size: 2rem; color: #38bdf8; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
            th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #334155; }}
            th {{ background: #0f172a; color: #94a3b8; }}
            .badge-confirmed {{ background: #dc2626; color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; }}
            .badge-flagged {{ background: #d97706; color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; }}
            a {{ color: #38bdf8; text-decoration: none; }}
        </style>
    </head>
    <body>
        <h1>🛡️ CyberForge — Multi-Agent PTES Engine</h1>
        <div class="grid">
            <div class="metric"><h2>{len(hosts)}</h2><p>Hosts Discovered</p></div>
            <div class="metric"><h2>{len(findings)}</h2><p>Total Findings</p></div>
            <div class="metric"><h2>{confirmed}</h2><p>Confirmed Weaknesses</p></div>
            <div class="metric"><h2>{len(steps)}</h2><p>Attack Path Steps</p></div>
        </div>

        <div class="card">
            <h3>Discovered Target Hosts</h3>
            <table>
                <tr><th>Host ID</th><th>IP Address</th><th>Open Ports</th><th>Tested Surfaces</th><th>Actions</th></tr>
                {"".join([f"<tr><td><code>{h.host_id}</code></td><td>{h.ip}</td><td>{', '.join([str(p.port) for p in h.ports]) or 'None'}</td><td>{', '.join(h.tested_surfaces) or 'None'}</td><td><a href='/targets/{h.host_id}/findings'>View Findings</a></td></tr>" for h in hosts]) or "<tr><td colspan='5'>Scanning network...</td></tr>"}
            </table>
        </div>

        <div class="card">
            <h3>Recent Findings</h3>
            <table>
                <tr><th>ID</th><th>Host</th><th>Title</th><th>Surface</th><th>Phase</th><th>Status</th></tr>
                {"".join([f"<tr><td><code>{f.id}</code></td><td>{f.host_ip}</td><td>{f.title}</td><td>{f.surface}</td><td>{f.ptes_phase}</td><td><span class='badge-{f.status.lower()}'>{f.status}</span></td></tr>" for f in findings]) or "<tr><td colspan='6'>No findings recorded yet.</td></tr>"}
            </table>
        </div>
        <p><a href="/report/markdown">View Full Markdown Report</a> | <a href="/report/json">Download JSON Summary</a></p>
    </body>
    </html>
    """
    return html


@app.get("/targets")
def list_targets():
    """List all discovered target hosts in scope."""
    if not engine_state:
        return []
    return [h.model_dump() for h in engine_state.list_hosts()]


@app.get("/targets/{target_id}")
def get_target(target_id: str):
    """Get target details by host_id."""
    if not engine_state:
        raise HTTPException(status_code=503, detail="State store uninitialized")
    host = engine_state.get_host(target_id)
    if not host:
        raise HTTPException(status_code=404, detail=f"Target {target_id} not found")
    return host.model_dump()


@app.get("/targets/{target_id}/findings")
def get_target_findings(target_id: str):
    """
    Required by FR-7: GET /targets/{id}/findings
    Returns verified and flagged findings for the designated target host.
    """
    if not engine_state:
        raise HTTPException(status_code=503, detail="State store uninitialized")

    findings = engine_state.get_findings(host_id=target_id)
    return [f.model_dump(mode="json") for f in findings]


@app.get("/findings")
def list_all_findings():
    """Returns all findings across all targets."""
    if not engine_state:
        return []
    return [f.model_dump(mode="json") for f in engine_state.get_findings()]


@app.get("/attack-path")
def get_attack_path():
    """Returns the ordered PTES attack path and step history."""
    if not engine_state:
        return []
    return [p.model_dump(mode="json") for p in engine_state.get_attack_path()]


@app.get("/report/json")
def get_report_json():
    """Full assessment report in JSON format."""
    if not report_gen:
        raise HTTPException(status_code=503, detail="Report generator uninitialized")
    return report_gen.generate_json_data()


@app.get("/report/markdown", response_class=PlainTextResponse)
def get_report_markdown():
    """Full assessment report in Markdown format."""
    if not report_gen:
        raise HTTPException(status_code=503, detail="Report generator uninitialized")
    return report_gen.generate_markdown_report()

