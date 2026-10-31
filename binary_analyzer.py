"""
binary_analyzer.py - Static Binary Vulnerability and Mitigation Audit Module.

Designed for authorized hackathon/CTF exercises analyzing organizer-provided sample binaries.
Enforces ScopeGate verification prior to command execution.
Executes and parses file, strings, and checksec --file outputs.
Identifies hardcoded credentials/secrets, memory-unsafe C standard library functions,
and missing stack canaries, recording all findings and marking 'binary' as a tested surface.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from scope import ScopeGate
import state

logger = logging.getLogger("cyberforge.binary_analyzer")

# Target memory-unsafe C standard library functions to detect
UNSAFE_C_FUNCTIONS: Dict[str, str] = {
    "strcpy": (
        "Memory-unsafe unbounded string copy function. Does not check destination buffer boundaries, "
        "enabling classic stack buffer overflows (CWE-120). Recommended replacement: strncpy or strlcpy."
    ),
    "gets": (
        "Inherently dangerous function that reads from stdin without buffer size limits (CWE-242). "
        "Guarantees buffer overflow vulnerability when input exceeds buffer size. Removed in C11."
    ),
    "sprintf": (
        "Formatted string print without destination size boundary checks (CWE-134/CWE-120). "
        "Allows buffer overflows and format string manipulation. Recommended replacement: snprintf."
    ),
    "system": (
        "Invokes system command processor (/bin/sh or cmd.exe) with full shell interpretation (CWE-78). "
        "Susceptible to command injection and argument spoofing if inputs are untrusted."
    ),
    "exec": (
        "Direct process execution function family. If arguments, binary path, or environment are derived "
        "from untrusted inputs, leads to arbitrary process execution or privilege escalation."
    ),
}

# Regex for AWS-style Access Key ID (AKIA + 16 alphanumeric uppercase chars)
AWS_KEY_REGEX = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")

# Regex for password/key assignment patterns
CREDENTIAL_ASSIGNMENT_REGEX = re.compile(
    r"""(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)\s*[:=]\s*["']?([^\s"';\n]{4,})["']?"""
)

# Regex to detect lack of stack canary from checksec output
CHECKSEC_NO_CANARY_REGEX = re.compile(
    r"(?:no canary found|stack:\s*no canary|canary:\s*(?:no|disabled|none)\b|canary.*disabled)",
    re.IGNORECASE,
)


def extract_strings(
    file_path: Union[str, Path],
    min_len: int = 4,
    runner: Optional[Callable[[List[str]], str]] = None,
) -> str:
    """
    Extract printable strings from a binary file using the `strings` utility,
    with a pure-Python fallback if the system binary is not available.
    """
    path_obj = Path(file_path)
    if not path_obj.is_file():
        raise FileNotFoundError(f"Binary file not found: {path_obj.resolve()}")

    if runner is not None:
        return runner(["strings", str(file_path)])

    strings_bin = shutil.which("strings")
    if strings_bin:
        try:
            proc = subprocess.run(
                [strings_bin, "-a", "-n", str(min_len), str(file_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if proc.stdout:
                return proc.stdout
        except Exception as e:
            logger.debug("System strings binary failed (%s), falling back to Python extraction.", e)

    # Pure-Python fallback: extract printable ASCII strings
    with open(path_obj, "rb") as f:
        data = f.read()

    pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    raw_matches = re.findall(pattern, data)
    return "\n".join(m.decode("ascii", errors="ignore") for m in raw_matches)


def run_file_utility(
    file_path: Union[str, Path],
    runner: Optional[Callable[[List[str]], str]] = None,
) -> str:
    """
    Execute `file` command-line utility against a binary path,
    falling back to header inspection if `file` is not installed.
    """
    path_obj = Path(file_path)
    if not path_obj.is_file():
        raise FileNotFoundError(f"Binary file not found: {path_obj.resolve()}")

    if runner is not None:
        return runner(["file", str(file_path)])

    file_bin = shutil.which("file")
    if file_bin:
        try:
            proc = subprocess.run(
                [file_bin, "-b", str(file_path)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if proc.stdout:
                return proc.stdout.strip()
        except Exception:
            pass

    # Pure-Python header fallback
    with open(path_obj, "rb") as f:
        magic = f.read(16)

    if magic.startswith(b"\x7fELF"):
        bits = "64-bit" if len(magic) > 4 and magic[4] == 2 else "32-bit"
        return f"ELF {bits} LSB executable"
    elif magic.startswith(b"MZ"):
        return "PE32/PE32+ executable (Windows)"
    elif magic.startswith(b"#!"):
        return "Script text executable"
    return "Data / unknown binary file"


def run_checksec_utility(
    file_path: Union[str, Path],
    runner: Optional[Callable[[List[str]], str]] = None,
) -> str:
    """
    Execute `checksec --file <path>` utility to audit binary mitigations.
    """
    path_obj = Path(file_path)
    if not path_obj.is_file():
        raise FileNotFoundError(f"Binary file not found: {path_obj.resolve()}")

    if runner is not None:
        return runner(["checksec", "--file", str(file_path)])

    checksec_bin = shutil.which("checksec")
    if checksec_bin:
        try:
            proc = subprocess.run(
                [checksec_bin, "--file", str(file_path)],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            return proc.stdout.strip()
        except Exception as e:
            logger.warning("checksec command failed: %s", e)

    return "checksec utility unavailable on system"


def scan_strings_for_secrets(strings_output: str) -> List[Dict[str, str]]:
    """
    Search strings output for hardcoded credentials, secret assignments,
    and AWS-style access keys using regex patterns.
    """
    secrets_found: List[Dict[str, str]] = []
    seen_evidence: Set[str] = set()

    # 1. AWS Access Key Pattern
    for match in AWS_KEY_REGEX.finditer(strings_output):
        ev = match.group(0)
        if ev not in seen_evidence:
            seen_evidence.add(ev)
            secrets_found.append({
                "type": "aws_access_key",
                "description": f"Hardcoded AWS-style Access Key ID detected: {ev[:8]}********",
                "evidence": ev,
            })

    # 2. Credential Assignment Pattern
    for match in CREDENTIAL_ASSIGNMENT_REGEX.finditer(strings_output):
        ev = match.group(0).strip()
        if ev not in seen_evidence:
            seen_evidence.add(ev)
            val = match.group(1)
            # Filter out generic template placeholders or trivial strings
            if val.lower() not in {"null", "none", "true", "false", "password", "secret"}:
                secrets_found.append({
                    "type": "hardcoded_credential",
                    "description": f"Hardcoded credential/secret assignment pattern detected in binary: '{ev}'",
                    "evidence": ev,
                })

    return secrets_found


def scan_strings_for_unsafe_c_functions(strings_output: str) -> List[Dict[str, str]]:
    """
    Search strings output for references to known memory-unsafe C standard library
    function names (strcpy, gets, sprintf, system, exec).
    """
    unsafe_matches: List[Dict[str, str]] = []
    seen_funcs: Set[str] = set()

    for func_name, explanation in UNSAFE_C_FUNCTIONS.items():
        # Match function name as an isolated token / symbol name
        pattern = rf"\b{re.escape(func_name)}\b"
        match = re.search(pattern, strings_output)
        if match and func_name not in seen_funcs:
            seen_funcs.add(func_name)
            unsafe_matches.append({
                "function": func_name,
                "description": f"Binary references memory-unsafe C standard library function '{func_name}'. {explanation}",
                "evidence": f"Symbol/String: {func_name}",
            })

    return unsafe_matches


def has_missing_stack_canary(checksec_output: str) -> bool:
    """
    Evaluate checksec text output to determine if stack canary protection is absent.
    """
    if not checksec_output or "checksec utility unavailable" in checksec_output:
        return False
    return bool(CHECKSEC_NO_CANARY_REGEX.search(checksec_output))


def analyze_binary(
    file_path: Union[str, Path],
    *,
    host_id: Optional[str] = None,
    gate: Optional[ScopeGate] = None,
    db_path: Union[str, Path] = state.DEFAULT_DB_PATH,
    runner: Optional[Callable[[List[str]], str]] = None,
) -> Dict[str, Any]:
    """
    Execute comprehensive static binary analysis against an in-scope binary file:
      1. Verifies ScopeGate authorization for the binary path.
      2. Executes file, strings, and checksec --file.
      3. Regex searches strings for hardcoded credentials / AWS access keys (Severity: High).
      4. Searches strings for memory-unsafe C functions (strcpy, gets, sprintf, system, exec) (Severity: Medium).
      5. Checks checksec output for missing stack canary (Severity: Low).
      6. Writes all findings into shared state.py and marks 'binary' as a tested surface.

    Parameters:
      file_path: Path to the target binary file.
      host_id: Associated host IP or identifier (defaults to '127.0.0.1' or file basename).
      gate: ScopeGate instance for authorization (defaults to ScopeGate.get_default()).
      db_path: Path to SQLite state database.
      runner: Optional custom execution runner (cmd: List[str]) -> stdout for testing.

    Returns:
      Dict with analysis summary, finding IDs, and extracted indicators.
    """
    path_obj = Path(file_path)
    file_name = path_obj.name
    target_host = host_id or "127.0.0.1"

    # 1. ScopeGate verification (Mandatory prior to running utilities)
    active_gate = gate or ScopeGate.get_default()

    if not active_gate.check_binary(str(file_path)):
        logger.warning("Binary analysis aborted: File '%s' rejected by ScopeGate.", file_path)
        return {
            "file": str(file_path),
            "success": False,
            "error": f"ScopeGate: Binary path '{file_path}' is not in the authorized scope.",
            "finding_ids": [],
        }

    # 2. Run command-line utilities (file, strings, checksec)
    file_info = run_file_utility(file_path, runner=runner)
    strings_out = extract_strings(file_path, runner=runner)
    checksec_out = run_checksec_utility(file_path, runner=runner)

    # 3. Register or ensure host record exists in state.db
    state.add_host(ip=target_host, on_conflict="ignore", db_path=db_path)

    # 4. Mark 'binary' as a tested surface for the host record
    state.append_tested_surface(host_id=target_host, surface="binary", allow_duplicates=False, db_path=db_path)

    finding_ids: List[int] = []

    # 5. Search for Hardcoded Credentials / Secrets (Severity: High, Phase: Vulnerability Analysis)
    secrets = scan_strings_for_secrets(strings_out)
    for sec in secrets:
        fid = state.insert_finding(
            host_id=target_host,
            surface=f"binary/{file_name}/secrets",
            type="hardcoded_credential",
            ptes_phase="Vulnerability Analysis",
            description=sec["description"],
            evidence=sec["evidence"],
            verified="unverified",
            severity="high",
            db_path=db_path,
        )
        finding_ids.append(fid)

    # 6. Search for Memory-Unsafe C Standard Library Functions (Severity: Medium, Phase: Vulnerability Analysis)
    unsafe_funcs = scan_strings_for_unsafe_c_functions(strings_out)
    for uf in unsafe_funcs:
        fid = state.insert_finding(
            host_id=target_host,
            surface=f"binary/{file_name}/unsafe_api",
            type="memory_unsafe_c_function",
            ptes_phase="Vulnerability Analysis",
            description=uf["description"],
            evidence=uf["evidence"],
            verified="unverified",
            severity="medium",
            db_path=db_path,
        )
        finding_ids.append(fid)

    # 7. Check for Missing Stack Canary in checksec output (Severity: Low, Phase: Vulnerability Analysis)
    if has_missing_stack_canary(checksec_out):
        canary_desc = (
            f"Binary '{file_name}' was compiled without stack canary protection (No canary found). "
            "Stack frames lack stack-smashing protection, permitting return address overwrite upon buffer overflow."
        )
        # Extract checksec snippet for evidence
        canary_evidence = "checksec: No canary found"
        for line in checksec_out.splitlines():
            if CHECKSEC_NO_CANARY_REGEX.search(line):
                canary_evidence = line.strip()
                break

        fid = state.insert_finding(
            host_id=target_host,
            surface=f"binary/{file_name}/mitigations",
            type="missing_stack_canary",
            ptes_phase="Vulnerability Analysis",
            description=canary_desc,
            evidence=canary_evidence,
            verified="unverified",
            severity="low",
            db_path=db_path,
        )
        finding_ids.append(fid)

    return {
        "file": str(file_path),
        "file_info": file_info,
        "success": True,
        "host_id": target_host,
        "tested_surfaces_updated": True,
        "secrets_count": len(secrets),
        "unsafe_functions_count": len(unsafe_funcs),
        "missing_stack_canary": has_missing_stack_canary(checksec_out),
        "finding_ids": finding_ids,
    }
