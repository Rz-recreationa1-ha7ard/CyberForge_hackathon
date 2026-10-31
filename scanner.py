"""
scanner.py - Nmap Service/Version Scanner with ScopeGate Enforcement and State Tracking.

Designed for authorized hackathon/CTF exercises against organizer-provided lab networks.
Performs scoped Nmap scanning (-sV), parses open ports, updates host state, and inserts
findings categorized by PTES phase (Intelligence Gathering vs Vulnerability Analysis).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from scope import ScopeGate, scoped
import state

logger = logging.getLogger("cyberforge.scanner")

# Default command-line configuration
DEFAULT_NMAP_TIMEOUT = 300  # 5 minutes
DEFAULT_NMAP_RETRIES = 2

# Inherently risky unauthenticated or cleartext services requiring Vulnerability Analysis tagging
RISKY_SERVICES: Dict[str, Dict[str, str]] = {
    "ftp": {
        "severity": "medium",
        "type": "cleartext_insecure_protocol",
        "reason": (
            "FTP transmits authentication credentials and commands in cleartext without encryption, "
            "exposing credentials to network eavesdropping, and frequently permits anonymous/unauthenticated logins."
        ),
    },
    "tftp": {
        "severity": "medium",
        "type": "unauthenticated_file_transfer",
        "reason": (
            "TFTP provides no authentication or authorization mechanisms by design, allowing unauthenticated "
            "file retrieval and modification over UDP."
        ),
    },
    "telnet": {
        "severity": "high",
        "type": "cleartext_remote_access",
        "reason": (
            "Telnet transmits all session traffic, administrative commands, and passwords in cleartext without "
            "confidentiality or integrity protection, vulnerable to sniffing and session hijacking."
        ),
    },
    "smb": {
        "severity": "medium",
        "type": "unauthenticated_smb_exposure",
        "reason": (
            "Exposed SMB/CIFS service allows unauthenticated null sessions, anonymous IPC$ share enumeration, "
            "and active domain/user reconnaissance."
        ),
    },
    "microsoft-ds": {
        "severity": "medium",
        "type": "unauthenticated_smb_exposure",
        "reason": (
            "Direct SMB over port 445 exposed without network segmentation risks unauthenticated null sessions, "
            "anonymous share access, and credential spraying."
        ),
    },
    "netbios-ssn": {
        "severity": "medium",
        "type": "unauthenticated_smb_exposure",
        "reason": (
            "NetBIOS Session Service (port 139) permits anonymous legacy Windows share enumeration and "
            "unauthenticated information gathering."
        ),
    },
    "samba": {
        "severity": "medium",
        "type": "unauthenticated_smb_exposure",
        "reason": (
            "Exposed Samba file sharing service allows unauthenticated guest/null session enumeration "
            "of shares, users, and printers."
        ),
    },
    "rlogin": {
        "severity": "high",
        "type": "legacy_r_command",
        "reason": (
            "Rlogin relies on weak IP-based / .rhosts trust relationships without cryptographic authentication "
            "and transmits all session data in cleartext."
        ),
    },
    "rsh": {
        "severity": "high",
        "type": "legacy_r_command",
        "reason": (
            "Remote Shell (RSH) executes arbitrary commands without encryption or strong authentication, "
            "relying on vulnerable host-based trust."
        ),
    },
    "rexec": {
        "severity": "high",
        "type": "legacy_r_command",
        "reason": (
            "Rexec transmits credentials and remote command execution streams over cleartext connections."
        ),
    },
    "finger": {
        "severity": "low",
        "type": "unauthenticated_user_enumeration",
        "reason": (
            "Finger service exposes local usernames, login times, and home directory details without authentication."
        ),
    },
}

# Regex to parse Nmap port table lines
# Example: "21/tcp   open  ftp     vsftpd 3.0.3"
PORT_LINE_REGEX = re.compile(
    r"^\s*(?P<port>\d+)/(?P<proto>tcp|udp|sctp)\s+(?P<state>open(?:\|filtered)?)\s+(?P<service>[^\s]+)(?:\s+(?P<version>.+))?$",
    re.IGNORECASE,
)


def is_risky_service(service_name: str) -> Optional[Dict[str, str]]:
    """
    Check if a detected service name matches a known inherently risky or
    unauthenticated service (FTP, Telnet, SMB, etc.).
    """
    if not service_name:
        return None
    s = service_name.lower().strip()
    return RISKY_SERVICES.get(s)


def parse_nmap_text(nmap_output: str) -> List[Dict[str, Any]]:
    """
    Parse standard Nmap text output from -sV service detection.

    Extracts a list of open ports with port number, service name, detected version,
    and protocol.

    Parameters:
      nmap_output: Plaintext stdout from nmap.

    Returns:
      List of dicts: [{"port": int, "service": str, "version": str, "protocol": str, "raw": str}, ...]
    """
    open_ports: List[Dict[str, Any]] = []

    for line in nmap_output.splitlines():
        match = PORT_LINE_REGEX.match(line)
        if not match:
            continue

        state_str = match.group("state").lower()
        if "open" not in state_str:
            continue

        port_num = int(match.group("port"))
        proto = match.group("proto").lower()
        service = match.group("service").strip()
        version = (match.group("version") or "").strip()

        open_ports.append({
            "port": port_num,
            "service": service,
            "version": version,
            "protocol": proto,
            "raw": line.strip(),
        })

    return open_ports


def record_scan_results(
    ip: str,
    open_ports: List[Dict[str, Any]],
    *,
    db_path: Union[str, Path] = state.DEFAULT_DB_PATH,
    raw_output: str = "",
) -> Dict[str, Any]:
    """
    Record parsed Nmap scan results into the shared SQLite store:
      1. Create or update the host record with its open_ports JSON array.
      2. Append 'network' to the host's tested_surfaces list.
      3. For each open port, insert a finding record:
         - Plain services -> ptes_phase 'Intelligence Gathering'
         - Risky services (FTP, Telnet, SMB without auth) -> ptes_phase 'Vulnerability Analysis'
    """
    # 1. Format open_ports for host record: [{"port": ..., "service": ..., "version": ...}]
    ports_payload = [
        {"port": p["port"], "service": p["service"], "version": p.get("version", "")}
        for p in open_ports
    ]
    state.update_host_ports(host_id=ip, open_ports=ports_payload, db_path=db_path)

    # 2. Add 'network' to host's tested_surfaces list
    state.append_tested_surface(host_id=ip, surface="network", allow_duplicates=False, db_path=db_path)

    # 3. Insert finding for each open port
    inserted_findings: List[int] = []

    for p in open_ports:
        port = p["port"]
        service = p["service"]
        version = p.get("version", "")
        proto = p.get("protocol", "tcp")
        raw_line = p.get("raw", f"{port}/{proto} open {service} {version}".strip())

        risky_info = is_risky_service(service)

        if risky_info:
            ptes_phase = "Vulnerability Analysis"
            finding_type = risky_info.get("type", "insecure_service_exposure")
            severity = risky_info.get("severity", "medium")
            desc = (
                f"Inherently risky service detected: {service.upper()} on port {port}/{proto} "
                f"({version or 'version not detected'}). {risky_info['reason']}"
            )
        else:
            ptes_phase = "Intelligence Gathering"
            finding_type = "service_discovery"
            severity = "info"
            ver_text = f"version '{version}'" if version else "version undetected"
            desc = f"Discovered open port {port}/{proto} running service '{service}' ({ver_text})."

        fid = state.insert_finding(
            host_id=ip,
            surface=f"network/{port}-{service}",
            type=finding_type,
            ptes_phase=ptes_phase,
            description=desc,
            evidence=raw_line,
            verified="unverified",
            severity=severity,
            db_path=db_path,
        )
        inserted_findings.append(fid)

    return {
        "ip": ip,
        "success": True,
        "open_ports_count": len(open_ports),
        "open_ports": ports_payload,
        "tested_surfaces_updated": True,
        "finding_ids": inserted_findings,
    }


def scan_host(
    ip: str,
    *,
    gate: Optional[ScopeGate] = None,
    nmap_bin: str = "nmap",
    timeout_seconds: int = DEFAULT_NMAP_TIMEOUT,
    max_retries: int = DEFAULT_NMAP_RETRIES,
    ports: Optional[str] = None,
    skip_ping: bool = True,
    db_path: Union[str, Path] = state.DEFAULT_DB_PATH,
    runner: Optional[Callable[[List[str], int], str]] = None,
) -> Dict[str, Any]:
    """
    Perform a scoped Nmap scan with service & version detection against an in-scope IP.

    Enforces ScopeGate verification before running.
    Executes Nmap with -sV, a reasonable timeout, and limited retries.
    Parses output and writes open ports, tested surface ('network'), and findings to SQLite state.

    Parameters:
      ip: Target host IP.
      gate: ScopeGate instance (defaults to shared/default scope.yaml).
      nmap_bin: Path or command name for Nmap binary.
      timeout_seconds: Maximum scan duration in seconds (defaults to 300s).
      max_retries: Number of port probe retries (defaults to 2).
      ports: Optional port specification string (e.g., '1-1024', '21,22,80,445').
      skip_ping: Treat hosts as online (-Pn); default True for lab/CTF networks.
      db_path: Path to state.db.
      runner: Optional custom execution function (cmd, timeout) -> stdout string for mocking/testing.

    Returns:
      Dict with scan status, open ports, and recorded finding IDs.
    """
    # 1. ScopeGate verification (Mandatory prior to scan execution)
    active_gate = gate or ScopeGate.get_default()

    if not active_gate.check_host(ip):
        logger.warning("Scan aborted: Host %s is OUT OF SCOPE or EXCLUDED.", ip)
        return {
            "ip": ip,
            "success": False,
            "error": "ScopeGate: Target IP is out of authorized scope or excluded.",
            "open_ports": [],
            "finding_ids": [],
        }

    # Verify binary permission if gate checks binaries
    if not active_gate.check_binary(nmap_bin):
        logger.warning("Scan aborted: Binary '%s' is not authorized in scope.", nmap_bin)
        return {
            "ip": ip,
            "success": False,
            "error": f"ScopeGate: Binary '{nmap_bin}' is not authorized.",
            "open_ports": [],
            "finding_ids": [],
        }

    # 2. Build Nmap command with service/version detection, timeout, and limited retries
    cmd = [
        nmap_bin,
        "-sV",
        "--max-retries", str(max_retries),
        "--host-timeout", f"{timeout_seconds}s",
    ]
    if skip_ping:
        cmd.append("-Pn")
    if ports:
        cmd.extend(["-p", str(ports)])
    cmd.append(ip)

    # 3. Execute Nmap
    raw_output = ""
    try:
        if runner is not None:
            raw_output = runner(cmd, timeout_seconds)
        else:
            # Resolve binary executable if running natively
            resolved_bin = shutil.which(nmap_bin) or nmap_bin
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 15,
                check=False,
            )
            raw_output = proc.stdout
            if proc.returncode != 0 and not raw_output:
                err_msg = proc.stderr.strip() or f"Nmap exited with code {proc.returncode}"
                return {
                    "ip": ip,
                    "success": False,
                    "error": err_msg,
                    "open_ports": [],
                    "finding_ids": [],
                }
    except FileNotFoundError:
        return {
            "ip": ip,
            "success": False,
            "error": f"Nmap binary '{nmap_bin}' was not found on system PATH.",
            "open_ports": [],
            "finding_ids": [],
        }
    except subprocess.TimeoutExpired:
        return {
            "ip": ip,
            "success": False,
            "error": f"Nmap scan timed out after {timeout_seconds} seconds.",
            "open_ports": [],
            "finding_ids": [],
        }
    except Exception as exc:
        return {
            "ip": ip,
            "success": False,
            "error": f"Execution error: {exc}",
            "open_ports": [],
            "finding_ids": [],
        }

    # 4. Parse text output
    open_ports = parse_nmap_text(raw_output)

    # 5. Write results into shared coordination store
    results = record_scan_results(
        ip=ip,
        open_ports=open_ports,
        db_path=db_path,
        raw_output=raw_output,
    )
    return results

