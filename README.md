# 🛡️ CyberForge — Autonomous Multi-Agent PTES Engine

CyberForge is an autonomous multi-agent penetration testing and security assessment framework designed for lab environments following the **Penetration Testing Execution Standard (PTES)**.

The engine coordinates specialized agents across three attack surfaces (**Network**, **Web**, and **Binary**), shares state via a centralized blackboard to avoid redundant work, validates findings, and generates unified attack-path reports with actionable remediation.

---

## 🚀 Quickstart (One-Command Startup)

### Option 1: Docker Compose (Recommended)
Point the engine to your scope in `config.yaml` and launch:
```bash
docker compose up --build
```

### Option 2: Local Python Execution
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the engine (defaults to Recon tier)
python main.py --tier recon --cidr 192.168.1.0/24
```

Once running, access the live dashboard at:
👉 **`http://localhost:8000/`**

---

## 🏗️ Architecture & Multi-Agent Coordination (FR-4)

The framework is organized into decoupled modules around a shared state blackboard:

```
[ config.yaml ] (Bonus B-4: Config-driven agents)
       │
       ▼
[ ScopeGate ] ─── Enforces strict CIDR boundary (Zero out-of-scope probes)
       │
       ▼
[ Orchestrator ] (Coordinator)
  ├── State Blackboard (Host deduplication, claiming, event handoffs)
  ├── Agents (Network Discovery, Web Surface, Binary Analysis, Verification)
  └── Reporting Engine & FastAPI Server (FR-7)
```

### Agent Handoff Lifecycle
1. **Scope Locking:** `ScopeGate` validates and seals target CIDR.
2. **Intelligence Gathering:** Network discovery identifies live hosts and open ports.
3. **Event Dispatch:** Discovered web ports trigger the Web Agent; binary files trigger the Binary Agent.
4. **Deduplication:** `state.claim_host()` prevents multiple agents from duplicate testing on the same surface.
5. **Verification (FR-6):** Flagged weaknesses undergo confirmation passes before marked as `CONFIRMED`.
6. **Consolidated Reporting (FR-7):** Automatically exports JSON and Markdown assessment reports.

---

## 📡 API Endpoints (FR-7)

The built-in FastAPI service provides endpoints to inspect findings programmatically:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Live web dashboard with overview metrics |
| `GET` | `/targets` | List all discovered target hosts in scope |
| `GET` | `/targets/{target_id}` | Detailed host information and open ports |
| `GET` | `/targets/{target_id}/findings` | **Findings for a specific target host (FR-7 requirement)** |
| `GET` | `/findings` | List all findings across all targets |
| `GET` | `/attack-path` | Ordered timeline of PTES actions taken |
| `GET` | `/report/json` | Consolidated assessment report in JSON |
| `GET` | `/report/markdown` | Full assessment report in Markdown |

---

## ⚙️ Configuration & Extensibility (Bonus B-4)

Modify `config.yaml` to configure target scope, enable/disable agents, or adjust timeouts:

```yaml
scope:
  allowed_cidrs:
    - "192.168.1.0/24"
  max_scan_timeout_seconds: 1200 # Under 20 minutes for Great tier

agents:
  - name: "network_discovery"
    role: "Network and Port Enumerator"
    surface: "network"
    enabled: true
  - name: "web_agent"
    role: "Web Application Surface Analyzer"
    surface: "web"
    enabled: true
```

---

## 📋 Evaluation Benchmarks

| Metric | Target | CyberForge Guarantee |
| :--- | :--- | :--- |
| **Scope Safety** | None (0 stray probes) | Enforced via pre-request `ScopeGate.enforce_scope()` check |
| **Autonomy** | Starts with one command | Fully autonomous pipeline initiated via `main.py` |
| **Methodology** | PTES Alignment | Every step and finding is explicitly tagged with its PTES phase |
| **Verification** | All findings proven | Findings clearly separated into `FLAGGED` vs `CONFIRMED` |

