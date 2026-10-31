import re
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

    FLAG_PATTERN = re.compile(r"(flag\{[^\s\}]+\}|CTF\{[^\s\}]+\})", re.IGNORECASE)

    def __init__(self, config: AgentConfig, state: SharedState, scope_gate: ScopeGate):
        super().__init__(config, state, scope_gate)
        self.max_depth = self.config.parameters.get("max_crawl_depth", 2)
        self.timeout = self.config.parameters.get("request_timeout_seconds", 3)
        self.max_pages = self.config.parameters.get("max_pages_to_crawl", 25)
        self.user_agent = self.config.parameters.get("user_agent", "CyberForge-WebAgent/1.0")

    def _fetch(self, url: str) -> Optional[tuple[int, Dict[str, str], str]]:
        """Safely fetches a URL respecting scope and timeout."""
        parsed = urllib.parse.urlparse(url)
        host_ip = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Pre-request scope boundary check
        if not self.is_target_in_scope(host_ip, port):
            self.logger.warning(f"ScopeGate blocked request to {url}")
            return None

        req = urllib.request.Request(
            url,
            headers={"User-Agent": self.user_agent}
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
        except Exception as e:
            self.logger.debug(f"Fetch failed for {url}: {e}")
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

            # Step 1: Root page fetch & Header Security Audit
            root_res = self._fetch(base_url)
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
        """Checks for common sensitive endpoints."""
        probe_paths = [
            "/robots.txt",
            "/admin",
            "/.git/HEAD",
            "/backup",
            "/phpinfo.php",
            "/config.php.bak"
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
                    verified=True,
                    status=FindingStatus.CONFIRMED,
                    remediation="Ensure proper rate-limiting, CSRF tokens, and MFA on login forms."
                )

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

