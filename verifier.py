"""
verifier.py - Security Finding Verification and Confirmation Engine.

Designed for authorized hackathon/CTF exercises confirming findings against lab targets.
Applies specific verification logic by finding type:
  - 'default_credential': Re-attempts authentication; marks 'confirmed' on success, 'unverified' on failure.
  - 'reflected_xss' / 'sql_injection': Re-sends payload; checks for expected marker string in response.
  - surface == 'binary': Marks 'confirmed' directly (static evidence is self-contained).
  - Any other type: Marks 'probable'.
Persists updated verification status back into SQLite via state.py.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import urllib.error
import urllib.parse
import urllib.request

from scope import ScopeGate
import state

logger = logging.getLogger("cyberforge.verifier")

DEFAULT_TIMEOUT = 10.0


def default_http_requester(
    url: str,
    method: str = "GET",
    data: Optional[Union[Dict[str, Any], str, bytes]] = None,
    auth: Optional[Tuple[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, str]:
    """
    Default HTTP requester using standard library urllib.

    Returns:
      Tuple of (status_code: int, response_body_text: str)
    """
    req_headers = {
        "User-Agent": "CyberForge-FindingVerifier/1.0",
        "Accept": "*/*",
    }
    if headers:
        req_headers.update(headers)

    # HTTP Basic Authentication header
    if auth:
        user, pwd = auth
        creds = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("ascii")
        req_headers["Authorization"] = f"Basic {creds}"

    # Prepare body payload
    body_bytes = None
    if data is not None:
        if isinstance(data, dict):
            body_bytes = urllib.parse.urlencode(data).encode("utf-8")
            if "Content-Type" not in req_headers:
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif isinstance(data, str):
            body_bytes = data.encode("utf-8")
        elif isinstance(data, bytes):
            body_bytes = data

    req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            return status, body
    except urllib.error.HTTPError as err:
        try:
            body = err.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return err.code, body
    except Exception as exc:
        logger.debug("HTTP request failed: %s", exc)
        return 0, f"Connection error: {exc}"


def parse_credential_evidence(evidence: str, host_id: str) -> Dict[str, Any]:
    """
    Parse authentication credentials and target URL from evidence.
    Supports JSON formatting or delimited text patterns.
    """
    evidence_str = (evidence or "").strip()

    # Try JSON format
    if evidence_str.startswith("{") and evidence_str.endswith("}"):
        try:
            data = json.loads(evidence_str)
            if isinstance(data, dict):
                user = data.get("username") or data.get("user") or ""
                pwd = data.get("password") or data.get("pass") or ""
                url = data.get("url") or f"http://{host_id}/login"
                method = data.get("method", "POST" if data.get("form") else "GET")
                return {
                    "username": user,
                    "password": pwd,
                    "url": url,
                    "method": method,
                    "auth_type": data.get("auth_type", "basic"),
                    "form_data": data.get("form_data"),
                }
        except Exception:
            pass

    # Delimited string format: e.g. "admin:password" or "user=admin pass=password url=http://..."
    url_match = re.search(r"https?://[^\s]+", evidence_str)
    url = url_match.group(0) if url_match else f"http://{host_id}/login"

    user_match = re.search(r"(?:user(?:name)?|login)\s*[:=]\s*([^\s;,]+)", evidence_str, re.IGNORECASE)
    pass_match = re.search(r"(?:pass(?:word)?|pwd)\s*[:=]\s*([^\s;,]+)", evidence_str, re.IGNORECASE)

    if user_match and pass_match:
        return {
            "username": user_match.group(1),
            "password": pass_match.group(1),
            "url": url,
            "method": "GET",
            "auth_type": "basic",
            "form_data": None,
        }

    # Colon separator fallback: "admin:admin"
    if ":" in evidence_str:
        parts = evidence_str.split(":", 1)
        return {
            "username": parts[0].strip(),
            "password": parts[1].strip(),
            "url": url,
            "method": "GET",
            "auth_type": "basic",
            "form_data": None,
        }

    return {
        "username": "",
        "password": "",
        "url": url,
        "method": "GET",
        "auth_type": "basic",
        "form_data": None,
    }


def parse_injection_evidence(evidence: str, host_id: str) -> Dict[str, Any]:
    """
    Parse request URL, payload, and expected marker string from injection evidence.
    Supports JSON or plain text formats.
    """
    evidence_str = (evidence or "").strip()

    # Try JSON format
    if evidence_str.startswith("{") and evidence_str.endswith("}"):
        try:
            data = json.loads(evidence_str)
            if isinstance(data, dict):
                url = data.get("url") or f"http://{host_id}/"
                payload = data.get("payload") or ""
                marker = data.get("marker") or payload
                method = data.get("method", "GET")
                post_data = data.get("data")
                return {
                    "url": url,
                    "payload": payload,
                    "marker": marker,
                    "method": method,
                    "data": post_data,
                }
        except Exception:
            pass

    # Text format: look for URL and Marker keywords
    url_match = re.search(r"https?://[^\s]+", evidence_str)
    url = url_match.group(0) if url_match else f"http://{host_id}/"

    marker_match = re.search(r"(?:marker|reflect(?:ed)?|expected)\s*[:=]\s*([^\n|]+)", evidence_str, re.IGNORECASE)
    payload_match = re.search(r"payload\s*[:=]\s*([^\n|]+)", evidence_str, re.IGNORECASE)

    payload = payload_match.group(1).strip() if payload_match else evidence_str
    marker = marker_match.group(1).strip() if marker_match else payload

    return {
        "url": url,
        "payload": payload,
        "marker": marker,
        "method": "GET",
        "data": None,
    }


def verify_finding(
    finding: Union[Dict[str, Any], int],
    *,
    gate: Optional[ScopeGate] = None,
    db_path: Union[str, Path] = state.DEFAULT_DB_PATH,
    requester: Optional[Callable[..., Tuple[int, str]]] = None,
) -> str:
    """
    Verify and confirm a security finding dictionary based on its type and surface:

      1. surface is 'binary' (or starts with 'binary'):
         -> Sets verified to 'confirmed' directly (static evidence is self-contained).

      2. type is 'default_credential':
         -> Re-attempts authentication with credentials in the evidence field.
         -> Sets verified to 'confirmed' only if authentication succeeds; otherwise 'unverified'.

      3. type is 'reflected_xss' or 'sql_injection':
         -> Re-sends exact request payload from evidence; checks if expected marker appears in response body.
         -> Sets verified to 'confirmed' if marker found; otherwise 'unverified'.

      4. Any other type:
         -> Sets verified to 'probable'.

    Persists the updated verification status back into the shared state database.

    Parameters:
      finding: Finding dictionary (or integer finding ID).
      gate: Optional ScopeGate instance for target host authorization.
      db_path: Path to SQLite coordination database.
      requester: Optional custom HTTP function (url, method, data, auth) -> (status_code, body) for testing.

    Returns:
      The updated verification status string ('confirmed', 'probable', or 'unverified').
    """
    # If finding ID is provided, retrieve dictionary from database
    if isinstance(finding, int):
        fetched = state.get_finding(finding, db_path=db_path)
        if not fetched:
            raise ValueError(f"Finding ID {finding} not found in state database.")
        finding_dict = fetched
    else:
        finding_dict = finding

    finding_id = finding_dict.get("id")
    finding_type = (finding_dict.get("type") or "").strip().lower()
    surface = (finding_dict.get("surface") or "").strip().lower()
    evidence = finding_dict.get("evidence") or ""
    host_id = str(finding_dict.get("host_id") or "").strip()

    req_func = requester or default_http_requester
    active_gate = gate or ScopeGate.get_default()

    new_status: str

    # Rule 1: Binary surface is self-contained static evidence -> 'confirmed' directly
    if surface == "binary" or surface.startswith("binary"):
        new_status = "confirmed"

    # Rule 2: default_credential -> re-attempt authentication
    elif finding_type == "default_credential":
        # Check ScopeGate before sending network request
        if host_id and not active_gate.check_host(host_id):
            logger.warning("Verification aborted: Host %s rejected by ScopeGate.", host_id)
            new_status = "unverified"
        else:
            cred_info = parse_credential_evidence(evidence, host_id)
            user = cred_info["username"]
            pwd = cred_info["password"]
            target_url = cred_info["url"]

            try:
                if cred_info.get("form_data"):
                    # Form-based authentication
                    status_code, body = req_func(
                        target_url,
                        method="POST",
                        data=cred_info["form_data"],
                    )
                else:
                    # HTTP Basic authentication
                    status_code, body = req_func(
                        target_url,
                        method="GET",
                        auth=(user, pwd),
                    )

                # Successful authentication: 2xx or 302 redirect without failure indications
                auth_succeeded = (
                    (200 <= status_code < 400)
                    and status_code not in (401, 403)
                    and not re.search(r"(?:invalid|incorrect|failed)\s+(?:password|credentials|login)", body, re.I)
                )

                new_status = "confirmed" if auth_succeeded else "unverified"
            except Exception as e:
                logger.debug("Credential verification error: %s", e)
                new_status = "unverified"

    # Rule 3: reflected_xss or sql_injection -> re-send payload and verify marker in response
    elif finding_type in ("reflected_xss", "sql_injection"):
        # Check ScopeGate before sending network request
        if host_id and not active_gate.check_host(host_id):
            logger.warning("Verification aborted: Host %s rejected by ScopeGate.", host_id)
            new_status = "unverified"
        else:
            inj_info = parse_injection_evidence(evidence, host_id)
            target_url = inj_info["url"]
            marker = inj_info["marker"]
            method = inj_info.get("method", "GET")
            post_data = inj_info.get("data")

            try:
                status_code, body = req_func(
                    target_url,
                    method=method,
                    data=post_data,
                )

                # Check whether expected marker string appears in response body
                marker_found = marker and (marker in body)
                new_status = "confirmed" if marker_found else "unverified"
            except Exception as e:
                logger.debug("Injection verification error: %s", e)
                new_status = "unverified"

    # Rule 4: Any other type -> set to 'probable'
    else:
        new_status = "probable"

    # Persist updated status back to state.py
    if finding_id is not None:
        state.update_finding_verification(finding_id, verified=new_status, db_path=db_path)
        finding_dict["verified"] = new_status

    return new_status


def verify_all_unverified(
    *,
    host_id: Optional[str] = None,
    gate: Optional[ScopeGate] = None,
    db_path: Union[str, Path] = state.DEFAULT_DB_PATH,
    requester: Optional[Callable[..., Tuple[int, str]]] = None,
) -> Dict[int, str]:
    """
    Iterate over unverified findings in the state store and apply verification logic.

    Returns:
      Dictionary mapping finding ID to its new verified status.
    """
    unverified_findings = state.list_findings(host_id=host_id, verified="unverified", db_path=db_path)
    results: Dict[int, str] = {}

    for finding in unverified_findings:
        fid = finding["id"]
        status = verify_finding(
            finding,
            gate=gate,
            db_path=db_path,
            requester=requester,
        )
        results[fid] = status

    return results

