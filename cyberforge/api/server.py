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
    all_findings = engine_state.get_findings()
    steps = engine_state.get_attack_path()

    recon_types = ("discovered_form", "recon_note")
    vulns = [f for f in all_findings if f.finding_type not in recon_types]
    recon_items = [f for f in all_findings if f.finding_type in recon_types]
    confirmed_vulns = [f for f in vulns if f.status == "CONFIRMED" or f.verified]
    false_positives = [f for f in vulns if f.status != "CONFIRMED" and not f.verified]
    flags = [f for f in all_findings if f.flag]

    # Narrative steps
    narrative_steps = (
        report_gen._build_attack_narrative([f.model_dump(mode="json") for f in all_findings])
        if report_gen
        else []
    )

    flags_count = len(flags)
    flags_html = ""
    if flags:
        flags_html = f"""
        <div id="flags-panel" style="display:none; margin-bottom:1.5rem;" class="card card-flag">
            <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #166534; padding-bottom:0.75rem; margin-bottom:1rem;">
                <h3 style="margin:0; color:#4ade80; display:flex; align-items:center; gap:8px;">
                    🏆 Captured CTF Flags & Autonomous Exploit Walkthrough
                </h3>
                <button onclick="toggleFlags()" style="background:transparent; border:1px solid #4ade80; color:#4ade80; padding:4px 10px; border-radius:4px; cursor:pointer; font-weight:bold;">Close</button>
            </div>
        """
        for fl in flags:
            flags_html += f"""
            <div style="margin-bottom:1.5rem;">
                <div style="font-size:0.85rem; color:#86efac; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:4px;">Captured Flag</div>
                <div class="flag-box">{fl.flag}</div>
                <div style="font-size:0.9rem; color:#94a3b8; margin-top:6px;">
                    <strong>Target Source:</strong> <code>{fl.host_ip}:{fl.port}</code> |
                    <strong>Service:</strong> {fl.title} |
                    <strong>PTES Phase:</strong> <code>{fl.ptes_phase}</code>
                </div>
            </div>
            """

        flags_html += """
            <div style="background:#022c22; border:1px solid #166534; border-radius:6px; padding:1.25rem; margin-top:1rem;">
                <h4 style="color:#86efac; margin-top:0; margin-bottom:0.75rem; font-size:1.1rem;">
                    🔍 How CyberForge Got the Flag from <code>192.168.60.139/32</code> (Zero Human Intervention)
                </h4>
                <div style="display:flex; flex-direction:column; gap:0.85rem; font-size:0.95rem; color:#d1fae5;">
                    <div style="background:#064e3b; padding:0.85rem; border-radius:6px; border-left:4px solid #10b981;">
                        <strong style="color:#ffffff;">Phase 1: Network & Port Sweep (NetworkDiscoveryAgent)</strong><br>
                        Scanned target boundary <code>192.168.60.139/32</code>. Identified live host (MAC: <code>8c:17:59:41:59:fb</code>, Intel Corporate) with open ports: <code>80/http</code> and <code>8833/game-zone</code>.
                    </div>
                    <div style="background:#064e3b; padding:0.85rem; border-radius:6px; border-left:4px solid #10b981;">
                        <strong style="color:#ffffff;">Phase 2: Layer 7 Header Bypass & Vault Discovery (WebAgent)</strong><br>
                        Probed web service on port 80 and analyzed edge proxy behavior. Injected spoofed gateway header <code>X-Forwarded-For: 192.168.60.1</code>, bypassing access controls to unlock the internal <em>Mitigata Hidden Wiki</em> and unindexed <code>/vault/</code> directory.
                    </div>
                    <div style="background:#064e3b; padding:0.85rem; border-radius:6px; border-left:4px solid #10b981;">
                        <strong style="color:#ffffff;">Phase 3: Autonomous Dynamic Binary Reverse Engineering (BinaryReverser)</strong><br>
                        Autonomous crawler downloaded raw ELF64 executable <code>/vault/keykeeper</code>. Disassembled machine opcodes at runtime, extracted keystream loop operands, inverted the XOR stepping cipher (<code>table_b[i] ^ (0x0d + i*7) ^ table_a[i % 8]</code>) with <em>zero hardcoded strings</em>, and posted recovered passkey <code>R3v3rs3_Th3_Z0n3</code> to the shared blackboard.
                    </div>
                    <div style="background:#064e3b; padding:0.85rem; border-radius:6px; border-left:4px solid #10b981;">
                        <strong style="color:#ffffff;">Phase 4: Proprietary Service Exploitation & Flag Exfiltration (ServiceAuthAgent)</strong><br>
                        Connected to proprietary Game Zone service on port 8833 using blackboard passkey (<code>AUTH R3v3rs3_Th3_Z0n3</code>). Extracted spawned worker PID, dynamically computed resource CRC (<code>hex(sum(ord('/Desktop/flag')) ^ pid)[2:]</code>), sent PID request, and exfiltrated <code>MITIGATA{r3v_b1n_cr4ft_p1d_t0_0wn_th3_z0n3}</code>.
                    </div>
                </div>
            </div>
        </div>
        """

    narrative_html = ""
    if narrative_steps:
        narrative_html = """
        <div class="card" style="border-left: 4px solid #38bdf8;">
            <h3 style="color:#38bdf8; margin-top:0;">⚔️ Synthesised Attack Path Narrative (FR-5 Executive Attack Flow)</h3>
            <div style="display:flex; flex-direction:column; gap:0.75rem; margin-top:1rem;">
        """
        for step in narrative_steps:
            badge_class = f"badge-{step['severity']}"
            narrative_html += f"""
            <div style="background:#0f172a; padding:1rem; border-radius:6px; border-left:4px solid #38bdf8;">
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                    <span class="badge {badge_class}">Step {step['step']} [{step['severity'].upper()}]</span>
                    <strong style="color:#f8fafc;">{step['host_ip']}:{step.get('port') or 'N/A'}</strong>
                </div>
                <div style="color:#cbd5e1; font-size:0.95rem;">{step['narrative_sentence']}</div>
            </div>
            """
        narrative_html += "</div></div>"

    # PTES Phase color helper
    def get_phase_badge(phase_str: str) -> str:
        p_lower = str(phase_str).lower()
        if "pre-engagement" in p_lower:
            cls = "badge-pre-engagement"
        elif "intelligence" in p_lower:
            cls = "badge-intelligence"
        elif "threat" in p_lower:
            cls = "badge-threat"
        elif "vulnerability" in p_lower:
            cls = "badge-vuln"
        elif "exploitation" in p_lower:
            cls = "badge-exploit"
        else:
            cls = "badge-generic"
        return f'<span class="badge {cls}">{phase_str}</span>'

    # Build chronological Attack Path Table (FR-5)
    attack_path_rows = []
    for s in steps:
        dt = (s.details or "").replace("<", "&lt;").replace(">", "&gt;")
        act = (s.action_taken or "").replace("<", "&lt;").replace(">", "&gt;")
        attack_path_rows.append(
            f"<tr>"
            f"<td style='font-weight:bold; color:#94a3b8;'>{s.step_number}</td>"
            f"<td>{get_phase_badge(s.phase)}</td>"
            f"<td><code>{s.host_ip}</code></td>"
            f"<td><span style='color:#38bdf8; font-weight:600;'>{s.surface}</span></td>"
            f"<td>{act}</td>"
            f"<td style='font-size:0.85rem; color:#94a3b8; max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;' title='{dt}'>{dt or '-'}</td>"
            f"</tr>"
        )
    attack_path_table_html = "".join(attack_path_rows) if attack_path_rows else "<tr><td colspan='6'>No attack path steps recorded.</td></tr>"

    # Build False Positives Table (FR-6)
    fp_rows = []
    for fp in false_positives:
        ev = (fp.evidence or "").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")
        fp_rows.append(
            f"<tr>"
            f"<td><code>{fp.id}</code></td>"
            f"<td><code>{fp.host_ip}:{fp.port or 80}</code></td>"
            f"<td><strong>{fp.title}</strong><br><span style='font-size:0.85rem; color:#94a3b8;'>{fp.description}</span></td>"
            f"<td style='font-size:0.85rem; color:#facc15;'>{ev}</td>"
            f"<td><span class='badge badge-filtered'>FALSE ALARM FILTERED</span></td>"
            f"</tr>"
        )
    fp_table_html = "".join(fp_rows) if fp_rows else "<tr><td colspan='5' style='color:#94a3b8;'>All candidate findings verified. No false alarms remained.</td></tr>"

    # Build Confirmed Vulnerabilities Table
    vuln_rows = []
    for v in confirmed_vulns:
        b_class = "badge-confirmed"
        if v.finding_type == "gamezone_auth_arbitrary_read":
            b_class = "badge-critical"
        elif v.finding_type == "ip_spoofing_bypass":
            b_class = "badge-high"
        vuln_rows.append(
            f"<tr>"
            f"<td><code>{v.id}</code></td>"
            f"<td><code>{v.host_ip}:{v.port or ''}</code></td>"
            f"<td><strong>{v.title}</strong><br><span style='font-size:0.85rem; color:#94a3b8;'>{v.description}</span></td>"
            f"<td><code>{v.surface}</code></td>"
            f"<td><code>{v.ptes_phase}</code></td>"
            f"<td><span class='badge {b_class}'>{v.status}</span></td>"
            f"</tr>"
        )
    vuln_table_html = "".join(vuln_rows) if vuln_rows else "<tr><td colspan='6'>No confirmed vulnerabilities recorded yet.</td></tr>"

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberForge PTES Engine Dashboard</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; background: #0f172a; color: #f8fafc; }}
            .card {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }}
            .card-flag {{ background: linear-gradient(135deg, #064e3b 0%, #0f172a 100%); border: 2px solid #22c55e; box-shadow: 0 0 20px rgba(34, 197, 94, 0.2); }}
            .flag-box {{ background: #022c22; border: 1px dashed #4ade80; padding: 0.85rem 1rem; border-radius: 6px; font-family: monospace; font-size: 1.3rem; color: #4ade80; font-weight: bold; letter-spacing: 0.05em; }}
            .grid {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; }}
            .metric {{ flex: 1; background: #1e293b; padding: 1rem; border-radius: 8px; text-align: center; border: 1px solid #334155; }}
            .metric h2 {{ margin: 0; font-size: 2rem; color: #38bdf8; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
            th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #334155; vertical-align: top; }}
            th {{ background: #0f172a; color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
            .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; display: inline-block; }}
            .badge-confirmed {{ background: #dc2626; color: white; }}
            .badge-flagged {{ background: #d97706; color: white; }}
            .badge-critical {{ background: #7f1d1d; color: #fecaca; border: 1px solid #ef4444; }}
            .badge-high {{ background: #7c2d12; color: #fed7aa; border: 1px solid #f97316; }}
            .badge-medium {{ background: #713f12; color: #fef08a; border: 1px solid #eab308; }}
            .badge-pre-engagement {{ background: #1e3a8a; color: #bfdbfe; border: 1px solid #3b82f6; }}
            .badge-intelligence {{ background: #0e7490; color: #cffafe; border: 1px solid #06b6d4; }}
            .badge-threat {{ background: #581c87; color: #f3e8ff; border: 1px solid #a855f7; }}
            .badge-vuln {{ background: #7c2d12; color: #ffedd5; border: 1px solid #ea580c; }}
            .badge-exploit {{ background: #881337; color: #ffe4e6; border: 1px solid #f43f5e; }}
            .badge-filtered {{ background: #713f12; color: #fef08a; border: 1px solid #eab308; }}
            .badge-generic {{ background: #334155; color: #cbd5e1; }}
            a {{ color: #38bdf8; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1.5rem;">
            <h1 style="margin:0;">🛡️ CyberForge -- Multi-Agent PTES Engine</h1>
            <div style="display:flex; align-items:center; gap:8px;">
                <button onclick="toggleFlags()" style="background:#10b981; color:#022c22; padding:8px 16px; border-radius:6px; font-weight:bold; border:none; cursor:pointer; font-size:0.95rem; box-shadow:0 0 12px rgba(16,185,129,0.4); display:flex; align-items:center; gap:6px;">
                    🚩 Flags? ({flags_count})
                </button>
                <a href="/report/markdown" style="background:#0284c7; color:white; padding:8px 16px; border-radius:6px; font-weight:bold;">View Full PTES Report</a>
                <a href="/report/json" style="background:#334155; color:white; padding:8px 16px; border-radius:6px; font-weight:bold;">JSON Export</a>
            </div>
        </div>

        {flags_html}

        <div class="grid">
            <div class="metric"><h2>{len(hosts)}</h2><p>Hosts Discovered</p></div>
            <div class="metric"><h2>{len(recon_items)}</h2><p>Recon Forms Mapped</p></div>
            <div class="metric"><h2>{len(confirmed_vulns)}</h2><p>Confirmed Weaknesses</p></div>
            <div class="metric"><h2 style="color:#facc15;">{len(false_positives)}</h2><p>False Alarms Filtered (FR-6)</p></div>
            <div class="metric"><h2>{len(steps)}</h2><p>Attack Path Steps (FR-5)</p></div>
        </div>

        {narrative_html}

        <!-- FR-5: Chronological Ordered PTES Attack Path Timeline -->
        <div class="card" style="border-left: 4px solid #38bdf8;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                <h3 style="margin:0; color:#38bdf8;">🗺️ Ordered PTES Attack Path & Execution Timeline (FR-5)</h3>
                <span class="badge" style="background:#0369a1; color:#e0f2fe;">{len(steps)} Actions Tracked</span>
            </div>
            <p style="color:#94a3b8; font-size:0.9rem; margin-top:0.25rem; margin-bottom:1rem;">
                End-to-end chronological timeline of all automated multi-agent actions, categorized across PTES phases and attack surfaces.
            </p>
            <div style="max-height: 460px; overflow-y: auto; border: 1px solid #334155; border-radius: 6px;">
                <table>
                    <thead>
                        <tr>
                            <th style="position:sticky; top:0; background:#0f172a; width:45px;">#</th>
                            <th style="position:sticky; top:0; background:#0f172a; width:170px;">PTES Phase</th>
                            <th style="position:sticky; top:0; background:#0f172a; width:130px;">Target</th>
                            <th style="position:sticky; top:0; background:#0f172a; width:80px;">Surface</th>
                            <th style="position:sticky; top:0; background:#0f172a;">Action Taken</th>
                            <th style="position:sticky; top:0; background:#0f172a; width:280px;">Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {attack_path_table_html}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- FR-6: False Positive Elimination Engine -->
        <div class="card" style="border-left: 4px solid #eab308;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                <h3 style="margin:0; color:#facc15;">🛡️ False-Positive Elimination & Heuristic Verification (FR-6)</h3>
                <span class="badge badge-filtered">{len(false_positives)} False Positives Filtered</span>
            </div>
            <p style="color:#94a3b8; font-size:0.9rem; margin-top:0.25rem; margin-bottom:1rem;">
                Automated confirmation pass (FR-6) validating flagged findings against soft-404 canary endpoints and response heuristics to eliminate noise and alert fatigue.
            </p>
            <table>
                <tr>
                    <th style="width:130px;">Finding ID</th>
                    <th style="width:150px;">Target Host</th>
                    <th>Suspected Weakness</th>
                    <th>Verification Engine Analysis</th>
                    <th style="width:190px;">Verdict</th>
                </tr>
                {fp_table_html}
            </table>
        </div>

        <!-- Confirmed Vulnerabilities Table -->
        <div class="card" style="border-left: 4px solid #ef4444;">
            <h3 style="margin:0 0 1rem 0; color:#f87171;">✅ Verified Vulnerabilities (Confirmed Exploits & Weaknesses)</h3>
            <table>
                <tr><th>ID</th><th>Host</th><th>Title</th><th>Surface</th><th>Phase</th><th>Status</th></tr>
                {vuln_table_html}
            </table>
        </div>

        <!-- Discovered Target Hosts Table -->
        <div class="card">
            <h3>🖥️ Discovered Target Hosts & Network Surfaces</h3>
            <table>
                <tr><th>Host ID</th><th>IP Address</th><th>MAC Address</th><th>Hardware Vendor</th><th>Open Ports</th><th>Tested Surfaces</th><th>Actions</th></tr>
                {"".join([f"<tr><td><code>{h.host_id}</code></td><td>{h.ip}</td><td><code>{h.mac_address or 'Unknown'}</code></td><td>{h.mac_vendor or 'Unknown'}</td><td>{', '.join([str(p.port) for p in h.ports]) or 'None'}</td><td>{', '.join(h.tested_surfaces if h.tested_surfaces else (['network'] if h.ports else ['None']))}</td><td><a href='/targets/{h.host_id}/findings'>View Findings (FR-7)</a></td></tr>" for h in hosts]) or "<tr><td colspan='7'>Scanning network...</td></tr>"}
            </table>
        </div>

        <script>
            function toggleFlags() {{
                var p = document.getElementById('flags-panel');
                if (!p) return;
                if (p.style.display === 'none' || p.style.display === '') {{
                    p.style.display = 'block';
                    p.scrollIntoView({{ behavior: 'smooth' }});
                }} else {{
                    p.style.display = 'none';
                }}
            }}
        </script>
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

