# 🛡️ CyberForge — Autonomous Multi-Agent PTES Engine

CyberForge is an autonomous, multi-agent penetration testing and security assessment engine designed for lab and enterprise environments following the **Penetration Testing Execution Standard (PTES)**.

The framework deploys specialized agents across three attack surfaces (**Network**, **Web**, and **Binary**), coordinates them via a centralized blackboard to eliminate redundant effort, actively validates findings with heuristic verification passes, and generates actionable, executive-ready attack-path reports.

---

## 🚀 Quickstart (One-Command Startup)

### Option 1: Local Python Execution (Recommended)
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the engine against your target scope (e.g., lab subnet or specific host)
python main.py --tier recon --cidr 192.168.60.x/x
# For a single host non-blocking run:
python main.py --tier recon --cidr 192.168.60.139/32 --no-wait
```
Once launched, the engine automatically runs all PTES phases and starts the live web dashboard at:  
👉 **`http://localhost:8000/`**

### Option 2: Standalone Web Dashboard Server
To review or present previously generated assessment reports without re-running a network sweep:
```bash
python serve_dashboard.py
```
Automatically loads the latest assessment report from `./reports/` and launches the interactive UI.

### Option 3: Docker Compose
```bash
docker compose up --build
```

---

## 📋 PTES Functional Requirements & Architecture

CyberForge strictly adheres to the PTES methodology across all modules:

```
[ config.yaml / config.json ] (Bonus B-4: Config-driven engine)
       │
       ▼
[ ScopeGate ] ─── Enforces strict CIDR boundary (Zero out-of-scope probes)
       │
       ▼
[ Orchestrator ] (Coordinator)
   ├── SharedState Blackboard (FR-4: Deduplication, claiming, cross-agent intel handoffs)
   ├── NetworkDiscoveryAgent (FR-1: Live hosts, ports, MAC/vendor resolution)
   ├── WebAgent (FR-2: Crawling, headers, form mapping, SQLi, proxy bypasses)
   ├── BinaryReverser (Runtime ELF64 disassembly, keystream recovery)
   ├── ServiceAuthAgent (Default credentials, dynamic PID CRC exploitation)
   ├── VerificationAgent (FR-6: False-positive elimination, soft-404 canary checks)
   └── ReportGenerator & FastAPI Server (FR-5, FR-7, B-3)
```

| Requirement | Module | Implementation Details |
| :--- | :--- | :--- |
| **FR-1: Network Reconnaissance** | `NetworkDiscoveryAgent` | Multi-threaded port sweep (21, 22, 23, 25, 53, 80, 443, 3306, 5432, 6379, 8080, 8443, 8833). Live host discovery, service banner grabbing, and MAC address IEEE OUI vendor resolution (e.g., `Intel Corporate`). |
| **FR-2: Web Surface Analysis** | `WebAgent` | Same-origin BFS web crawling with cycle detection. Audits security headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`). Catalogs forms and input fields. Injects benign canaries for input reflection and SQLi heuristics. Audits reverse proxy headers (`X-Forwarded-For`). Includes socket retry and cooldown backoff. |
| **FR-4: Multi-Agent Blackboard** | `SharedState` & `Orchestrator` | Central state blackboard supporting host deduplication, surface claiming (`claim_host`, `release_host`), pub-sub event dispatching, and cross-agent intel handoffs (`set_intel`, `get_intel`). |
| **FR-5: Attack Path Timeline** | `SharedState` & `ReportGenerator` | Chronological tracking of every atomic agent action (110+ steps) tagged with PTES phase, target host/port, surface, action taken, and technical details. |
| **FR-6: False-Positive Elimination** | `VerificationAgent` | Autonomous verification engine that re-probes flagged vulnerabilities. Validates exposed files against randomized canary endpoints and content hashes to distinguish true findings from soft-404 false alarms. |
| **FR-7: API & Reporting** | `server.py` & `generator.py` | Built-in FastAPI server with REST endpoints (`/targets`, `/targets/{id}/findings`, `/attack-path`, `/report/json`, `/report/markdown`) and comprehensive markdown/JSON reporting. |
| **Bonus B-1: CTF Flag Capture** | All Surface Agents | Multi-surface regex extraction (`(flag\{...\}|CTF\{...\}|MITIGATA\{...\})`) across network banners, web pages, and exploitation payloads. |
| **Bonus B-3: Synthesised Narrative** | `ReportGenerator` | Priority-ordered, plain-English attack narrative reconstructing the attacker's killchain with actionable remediation guidance. |
| **Bonus B-4: Config Extensibility** | `config.yaml` / `config.json` | Declarative YAML/JSON configuration controlling target scope, agent parameters, timeouts, and report options. |

---

## 🖥️ Live Web Dashboard Features (`http://localhost:8000`)

The built-in web dashboard provides real-time visibility into the penetration test:
* **Executive Metrics Grid:** Displays Hosts Discovered, Recon Forms Mapped, Confirmed Weaknesses, False Alarms Filtered (FR-6), and Attack Path Steps (FR-5).
* **🚩 Flags? Button:** An interactive toggle in the header that expands the **Captured CTF Flags & Autonomous Exploit Walkthrough**, revealing the captured flag and the 4-phase technical killchain.
* **🗺️ Ordered PTES Attack Path Timeline (FR-5):** A scrollable audit trail tracking all actions chronologically with color-coded PTES phase badges.
* **🛡️ False-Positive Elimination Table (FR-6):** Displays audited candidate vulnerabilities (e.g., `/.env` soft-404) with heuristic verification proof explaining why false alarms were suppressed.
* **✅ Verified Vulnerabilities Matrix:** Filtered table of confirmed weaknesses with CVSS severity badges and technical details.
* **🖥️ Discovered Target Hosts:** Full host inventory showing Host ID, IP, MAC Address, Hardware Vendor, Open Ports, Tested Surfaces, and individual target finding links (`/targets/{id}/findings`).

---

## 📡 REST API Reference (FR-7)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Interactive PTES web dashboard |
| `GET` | `/targets` | List all discovered target hosts in scope |
| `GET` | `/targets/{target_id}` | Detailed host information, MAC vendor, and open ports |
| `GET` | `/targets/{target_id}/findings` | **Specific target findings list (FR-7 requirement)** |
| `GET` | `/findings` | List all confirmed and flagged findings across all targets |
| `GET` | `/attack-path` | Ordered timeline of all PTES actions taken (FR-5) |
| `GET` | `/report/json` | Consolidated assessment report in JSON format |
| `GET` | `/report/markdown` | Full executive and technical PTES report in Markdown |

---

## 🧪 Test Suite & Verification

CyberForge includes unit and integration tests covering all agents, scope gating, blackboard events, verification heuristics, and report generation:

```bash
# Run the complete test suite
python -m unittest discover tests
```
* **Status:** 45/45 tests passing (`OK in ~8.2s`).

---

## 🔒 Scope & Safety Guarantees

* **Zero Stray Network Packets:** Every socket connection, HTTP request, and credential probe passes through `ScopeGate.is_in_scope()` prior to dispatch. Probes targeting out-of-scope addresses are aborted before touching the network.
* **Read-Safe Probing:** Benign inputs and non-destructive payloads are used during vulnerability analysis and canary verification.
