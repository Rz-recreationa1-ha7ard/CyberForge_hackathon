"""
state.py - SQLite-backed Shared Coordination Store for Multi-Component Security Automation.

Designed for authorized hackathon/CTF exercises with organizer-defined scope.
Tracks discovered hosts, port scans, tested surfaces, security findings, and attack paths.
Provides atomic host claiming for concurrent multi-component agents.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
from typing import Any, Dict, Generator, List, Optional, Union

# Default SQLite database path (can be overridden via CYBERFORGE_DB or function args)
DEFAULT_DB_PATH = os.environ.get("CYBERFORGE_DB", "state.db")

# Allowed states for finding verification vocabulary
VALID_VERIFIED_STATES = ("confirmed", "probable", "unverified")

# Fixed ordering for PTES execution phases
PTES_PHASE_ORDER: Dict[str, int] = {
    "intelligence gathering": 1,
    "vulnerability analysis": 2,
    "exploitation": 3,
    "post-exploitation": 4,
    "post exploitation": 4,
}


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def configure_connection(conn: sqlite3.Connection, timeout: float = 30.0) -> sqlite3.Connection:
    """
    Configure a SQLite connection for optimal concurrency and integrity:
      - WAL mode: Enables concurrent readers and a non-blocking writer.
      - busy_timeout: Retries locked operations rather than failing immediately.
      - foreign_keys: Enforces relational constraints across tables.
      - Row factory: Returns dict-like rows for easy attribute access.
    """
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {int(timeout * 1000)};")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def get_connection(
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    timeout: float = 30.0,
    auto_commit: bool = True,
) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager providing a configured SQLite connection.
    Commits automatically on exit unless an exception occurs.
    """
    conn = sqlite3.connect(
        str(db_path),
        timeout=timeout,
        check_same_thread=False,
        isolation_level=None if not auto_commit else "",
    )
    configure_connection(conn, timeout=timeout)
    try:
        yield conn
        if auto_commit:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Union[str, Path] = DEFAULT_DB_PATH) -> None:
    """
    Initialize SQLite database schema with three core coordination tables:
      1. hosts: Discovered hosts, status, claiming agent, tested surfaces, open ports.
      2. findings: Discovered vulnerabilities/observations linked to a host.
      3. attack_path: Step-by-step exploit chain / pivot progression linking findings.
    """
    db_file = Path(db_path)
    if db_file.parent and not db_file.parent.exists():
        db_file.parent.mkdir(parents=True, exist_ok=True)

    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        # 1. hosts table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                id TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'discovered',
                claimed_by TEXT,
                tested_surfaces TEXT NOT NULL DEFAULT '[]',
                open_ports TEXT NOT NULL DEFAULT '[]',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_claimed_by ON hosts(claimed_by);")

        # 2. findings table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id TEXT NOT NULL,
                surface TEXT,
                type TEXT,
                ptes_phase TEXT,
                description TEXT,
                evidence TEXT,
                verified TEXT NOT NULL DEFAULT 'unverified' CHECK(verified IN ('confirmed', 'probable', 'unverified')),
                severity TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_host_id ON findings(host_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_verified ON findings(verified);")

        # 3. attack_path table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_path (
                step INTEGER NOT NULL,
                finding_id INTEGER NOT NULL,
                leads_to_finding_id INTEGER,
                notes TEXT,
                FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
                FOREIGN KEY (leads_to_finding_id) REFERENCES findings(id) ON DELETE SET NULL
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_attack_path_step ON attack_path(step);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_attack_path_finding_id ON attack_path(finding_id);")


# ---------------------------------------------------------------------------
# Host Operations
# ---------------------------------------------------------------------------

def add_host(
    ip: str,
    status: str = "discovered",
    claimed_by: Optional[str] = None,
    tested_surfaces: Optional[Union[List[str], str]] = None,
    open_ports: Optional[Union[List[Dict[str, Any]], str]] = None,
    host_id: Optional[str] = None,
    on_conflict: str = "ignore",
    *,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    conn: Optional[sqlite3.Connection] = None,
) -> str:
    """
    Insert a discovered host into the coordination store.

    Parameters:
      ip: Host IP address.
      status: Defaults to 'discovered'.
      claimed_by: Initial claiming agent (if any).
      tested_surfaces: List or JSON string of tested surface tags. Default '[]'.
      open_ports: List of dicts [{"port": int, "service": str, "version": str}] or JSON string. Default '[]'.
      host_id: Host identifier (defaults to IP address).
      on_conflict: 'ignore' (default) or 'replace'.
    """
    hid = host_id or ip

    if tested_surfaces is None:
        surfaces_json = "[]"
    elif isinstance(tested_surfaces, str):
        surfaces_json = tested_surfaces
    else:
        surfaces_json = json.dumps(list(tested_surfaces))

    if open_ports is None:
        ports_json = "[]"
    elif isinstance(open_ports, str):
        ports_json = open_ports
    else:
        ports_json = json.dumps(list(open_ports))

    conflict_clause = "OR IGNORE" if on_conflict.lower() == "ignore" else "OR REPLACE"
    sql = f"""
        INSERT {conflict_clause} INTO hosts (
            id, ip, status, claimed_by, tested_surfaces, open_ports, first_seen, last_updated
        ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
    """
    params = (hid, ip, status, claimed_by, surfaces_json, ports_json)

    if conn is not None:
        conn.execute(sql, params)
        conn.commit()
    else:
        with get_connection(db_path) as c:
            c.execute(sql, params)

    return hid


def claim_host(
    host_id: str,
    agent_name: str,
    db_path: Optional[Union[str, Path, sqlite3.Connection]] = None,
    conn: Optional[sqlite3.Connection] = None,
    new_status: str = "claimed",
) -> bool:
    """
    Atomically claims a host record ONLY if its status is currently 'discovered'.

    Uses a single UPDATE statement with a WHERE clause checking the current status.
    Returns True only if the calling process's update actually changed a row
    (so concurrent callers can tell if they won the race).

    Parameters:
      host_id: IP address / primary key of the target host.
      agent_name: Identifier of the agent claiming the host.
      db_path: Optional path to SQLite database.
      conn: Optional existing sqlite3.Connection to reuse.
      new_status: Status to set upon successful claim (defaults to 'claimed').

    Returns:
      True if the caller successfully won the race and claimed the host, False otherwise.
    """
    if isinstance(db_path, sqlite3.Connection):
        conn = db_path
        actual_db_path = DEFAULT_DB_PATH
    else:
        actual_db_path = db_path or DEFAULT_DB_PATH

    sql = """
        UPDATE hosts
        SET status = ?,
            claimed_by = ?,
            last_updated = CURRENT_TIMESTAMP
        WHERE id = ? AND status = 'discovered';
    """
    params = (new_status, agent_name, host_id)

    if conn is not None:
        cursor = conn.execute(sql, params)
        conn.commit()
        return cursor.rowcount > 0
    else:
        with get_connection(actual_db_path) as c:
            cursor = c.execute(sql, params)
            return cursor.rowcount > 0


def release_host(
    host_id: str,
    agent_name: Optional[str] = None,
    new_status: str = "discovered",
    *,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    conn: Optional[sqlite3.Connection] = None,
) -> bool:
    """
    Release a claimed host (e.g. back to 'discovered' or mark as 'completed').
    Optionally checks that the agent releasing the host was the one who claimed it.
    """
    if agent_name:
        sql = """
            UPDATE hosts
            SET status = ?,
                claimed_by = NULL,
                last_updated = CURRENT_TIMESTAMP
            WHERE id = ? AND claimed_by = ?;
        """
        params = (new_status, host_id, agent_name)
    else:
        sql = """
            UPDATE hosts
            SET status = ?,
                claimed_by = NULL,
                last_updated = CURRENT_TIMESTAMP
            WHERE id = ?;
        """
        params = (new_status, host_id)

    if conn is not None:
        cursor = conn.execute(sql, params)
        conn.commit()
        return cursor.rowcount > 0
    else:
        with get_connection(db_path) as c:
            cursor = c.execute(sql, params)
            return cursor.rowcount > 0


def update_host_ports(
    host_id: str,
    open_ports: Union[List[Dict[str, Any]], str],
    *,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    conn: Optional[sqlite3.Connection] = None,
) -> bool:
    """
    Update open_ports for an existing host, or insert host if not found.
    Preserves existing status, claimed_by, and tested_surfaces.
    """
    if isinstance(open_ports, str):
        ports_json = open_ports
    else:
        ports_json = json.dumps(list(open_ports))

    def _do(c: sqlite3.Connection) -> bool:
        sql_update = """
            UPDATE hosts
            SET open_ports = ?,
                last_updated = CURRENT_TIMESTAMP
            WHERE id = ?;
        """
        cursor = c.execute(sql_update, (ports_json, host_id))
        if cursor.rowcount == 0:
            sql_insert = """
                INSERT INTO hosts (id, ip, status, open_ports, first_seen, last_updated)
                VALUES (?, ?, 'discovered', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
            """
            c.execute(sql_insert, (host_id, host_id, ports_json))
        c.commit()
        return True

    if conn is not None:
        return _do(conn)
    else:
        with get_connection(db_path) as c:
            return _do(c)


def append_tested_surface(
    host_id: str,
    surface: str,
    *,
    allow_duplicates: bool = True,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    conn: Optional[sqlite3.Connection] = None,
) -> bool:
    """
    Append a new value into a host's tested_surfaces JSON array.

    Uses SQLite's json_insert function to perform an atomic in-place append
    and updates the last_updated timestamp.
    """
    if allow_duplicates:
        sql = """
            UPDATE hosts
            SET tested_surfaces = json_insert(
                    CASE
                        WHEN tested_surfaces IS NULL OR json_valid(tested_surfaces) = 0 THEN '[]'
                        ELSE tested_surfaces
                    END,
                    '$[#]',
                    ?
                ),
                last_updated = CURRENT_TIMESTAMP
            WHERE id = ?;
        """
        params = (surface, host_id)
    else:
        sql = """
            UPDATE hosts
            SET tested_surfaces = json_insert(
                    CASE
                        WHEN tested_surfaces IS NULL OR json_valid(tested_surfaces) = 0 THEN '[]'
                        ELSE tested_surfaces
                    END,
                    '$[#]',
                    ?
                ),
                last_updated = CURRENT_TIMESTAMP
            WHERE id = ?
              AND NOT EXISTS (
                  SELECT 1 FROM json_each(
                      CASE
                          WHEN tested_surfaces IS NULL OR json_valid(tested_surfaces) = 0 THEN '[]'
                          ELSE tested_surfaces
                      END
                  ) WHERE value = ?
              );
        """
        params = (surface, host_id, surface)

    if conn is not None:
        cursor = conn.execute(sql, params)
        conn.commit()
        return cursor.rowcount > 0
    else:
        with get_connection(db_path) as c:
            cursor = c.execute(sql, params)
            return cursor.rowcount > 0


def get_host(
    host_id: str,
    *,
    parse_json: bool = True,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve a single host record by ID, optionally parsing JSON array fields."""
    sql = "SELECT * FROM hosts WHERE id = ?;"

    def _fetch(c: sqlite3.Connection):
        row = c.execute(sql, (host_id,)).fetchone()
        if not row:
            return None
        res = dict(row)
        if parse_json:
            try:
                res["tested_surfaces"] = json.loads(res.get("tested_surfaces") or "[]")
            except Exception:
                pass
            try:
                res["open_ports"] = json.loads(res.get("open_ports") or "[]")
            except Exception:
                pass
        return res

    if conn is not None:
        return _fetch(conn)
    else:
        with get_connection(db_path) as c:
            return _fetch(c)


def list_hosts(
    status: Optional[str] = None,
    claimed_by: Optional[str] = None,
    *,
    parse_json: bool = True,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    conn: Optional[sqlite3.Connection] = None,
) -> List[Dict[str, Any]]:
    """Query hosts with optional filters for status or claimed_by."""
    clauses = []
    params = []
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    if claimed_by is not None:
        clauses.append("claimed_by = ?")
        params.append(claimed_by)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"SELECT * FROM hosts {where} ORDER BY first_seen ASC;"

    def _fetch(c: sqlite3.Connection):
        rows = c.execute(sql, params).fetchall()
        results = []
        for row in rows:
            res = dict(row)
            if parse_json:
                try:
                    res["tested_surfaces"] = json.loads(res.get("tested_surfaces") or "[]")
                except Exception:
                    pass
                try:
                    res["open_ports"] = json.loads(res.get("open_ports") or "[]")
                except Exception:
                    pass
            results.append(res)
        return results

    if conn is not None:
        return _fetch(conn)
    else:
        with get_connection(db_path) as c:
            return _fetch(c)


# ---------------------------------------------------------------------------
# Findings Operations
# ---------------------------------------------------------------------------

def insert_finding(
    host_id: str,
    surface: Optional[str] = None,
    type: Optional[str] = None,
    ptes_phase: Optional[str] = None,
    description: Optional[str] = None,
    evidence: Optional[str] = None,
    verified: str = "unverified",
    severity: Optional[str] = None,
    timestamp: Optional[str] = None,
    *,
    finding_type: Optional[str] = None,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    conn: Optional[sqlite3.Connection] = None,
    **kwargs: Any,
) -> int:
    """
    Insert a security finding record associated with a host.

    Parameters:
      host_id: Foreign key referencing hosts(id).
      surface: The surface where the finding was identified (e.g., 'http-admin-panel').
      type: Type of finding (e.g., 'cve-2021-44228', 'default-credentials').
      ptes_phase: PTES phase (e.g., 'Vulnerability Analysis', 'Exploitation').
      description: Detailed summary of the observation.
      evidence: Terminal snippet, HTTP request/response, proof-of-concept output.
      verified: Status defaulting to 'unverified'. Must be one of: 'confirmed', 'probable', 'unverified'.
      severity: e.g., 'info', 'low', 'medium', 'high', 'critical'.
      timestamp: Optional custom timestamp; defaults to CURRENT_TIMESTAMP.
      finding_type: Keyword alias for type.

    Returns:
      The auto-incremented primary key ID of the created finding.
    """
    if verified not in VALID_VERIFIED_STATES:
        raise ValueError(
            f"Invalid verification status '{verified}'. Must be one of {VALID_VERIFIED_STATES}."
        )

    resolved_type = finding_type if finding_type is not None else type
    if resolved_type is None and "finding_type" in kwargs:
        resolved_type = kwargs["finding_type"]

    if timestamp is not None:
        sql = """
            INSERT INTO findings (
                host_id, surface, type, ptes_phase, description, evidence, verified, severity, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        params = (host_id, surface, resolved_type, ptes_phase, description, evidence, verified, severity, timestamp)
    else:
        sql = """
            INSERT INTO findings (
                host_id, surface, type, ptes_phase, description, evidence, verified, severity, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);
        """
        params = (host_id, surface, resolved_type, ptes_phase, description, evidence, verified, severity)

    if conn is not None:
        cursor = conn.execute(sql, params)
        conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]
    else:
        with get_connection(db_path) as c:
            cursor = c.execute(sql, params)
            return cursor.lastrowid  # type: ignore[return-value]


# Alias for intuitive discovery
add_finding = insert_finding


def update_finding_verification(
    finding_id: int,
    verified: str = "confirmed",
    *,
    status: Optional[str] = None,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    conn: Optional[sqlite3.Connection] = None,
) -> bool:
    """
    Update a finding's verification status field.
    Must be one of the three required states: 'confirmed', 'probable', or 'unverified'.

    Parameters:
      finding_id: ID of the finding to update.
      verified: New verification status string (defaults to 'confirmed').
      status: Keyword alias for verified.
      db_path: Optional path to SQLite database.
      conn: Optional existing sqlite3.Connection.

    Returns:
      True if the finding was found and updated, False otherwise.
    """
    new_verified_status = status if status is not None else verified
    if new_verified_status not in VALID_VERIFIED_STATES:
        raise ValueError(
            f"Invalid verification status '{new_verified_status}'. Must be one of {VALID_VERIFIED_STATES}."
        )

    sql = "UPDATE findings SET verified = ? WHERE id = ?;"
    params = (new_verified_status, finding_id)

    if conn is not None:
        cursor = conn.execute(sql, params)
        conn.commit()
        return cursor.rowcount > 0
    else:
        with get_connection(db_path) as c:
            cursor = c.execute(sql, params)
            return cursor.rowcount > 0


def get_finding(
    finding_id: int,
    *,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve a single finding by ID."""
    sql = "SELECT * FROM findings WHERE id = ?;"

    def _fetch(c: sqlite3.Connection):
        row = c.execute(sql, (finding_id,)).fetchone()
        return dict(row) if row else None

    if conn is not None:
        return _fetch(conn)
    else:
        with get_connection(db_path) as c:
            return _fetch(c)


def list_findings(
    host_id: Optional[str] = None,
    verified: Optional[str] = None,
    severity: Optional[str] = None,
    *,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    conn: Optional[sqlite3.Connection] = None,
) -> List[Dict[str, Any]]:
    """List findings with optional filters for host_id, verified status, or severity."""
    clauses = []
    params = []
    if host_id is not None:
        clauses.append("host_id = ?")
        params.append(host_id)
    if verified is not None:
        clauses.append("verified = ?")
        params.append(verified)
    if severity is not None:
        clauses.append("severity = ?")
        params.append(severity)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"SELECT * FROM findings {where} ORDER BY id ASC;"

    def _fetch(c: sqlite3.Connection):
        return [dict(row) for row in c.execute(sql, params).fetchall()]

    if conn is not None:
        return _fetch(conn)
    else:
        with get_connection(db_path) as c:
            return _fetch(c)


# ---------------------------------------------------------------------------
# Attack Path Operations
# ---------------------------------------------------------------------------

def add_attack_path_step(
    step: int,
    finding_id: int,
    leads_to_finding_id: Optional[int] = None,
    notes: Optional[str] = None,
    *,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    """
    Record an attack path progression step linking findings.

    Parameters:
      step: Step sequence number (e.g. 1, 2, 3).
      finding_id: ID of the base finding enabling this step.
      leads_to_finding_id: Optional ID of the subsequent finding or pivot reached.
      notes: Contextual notes or exploit command details.
    """
    sql = """
        INSERT INTO attack_path (step, finding_id, leads_to_finding_id, notes)
        VALUES (?, ?, ?, ?);
    """
    params = (step, finding_id, leads_to_finding_id, notes)

    if conn is not None:
        conn.execute(sql, params)
        conn.commit()
    else:
        with get_connection(db_path) as c:
            c.execute(sql, params)


def get_attack_path(
    *,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    conn: Optional[sqlite3.Connection] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve all recorded attack path steps ordered by step number,
    including linked finding descriptions.
    """
    sql = """
        SELECT
            ap.step,
            ap.finding_id,
            f1.description AS finding_description,
            f1.host_id AS finding_host_id,
            ap.leads_to_finding_id,
            f2.description AS leads_to_description,
            f2.host_id AS leads_to_host_id,
            ap.notes
        FROM attack_path ap
        JOIN findings f1 ON ap.finding_id = f1.id
        LEFT JOIN findings f2 ON ap.leads_to_finding_id = f2.id
        ORDER BY ap.step ASC;
    """

    def _fetch(c: sqlite3.Connection):
        return [dict(row) for row in c.execute(sql).fetchall()]

    if conn is not None:
        return _fetch(conn)
    else:
        with get_connection(db_path) as c:
            return _fetch(c)


def build_attack_path(
    *,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    conn: Optional[sqlite3.Connection] = None,
    clear_existing: bool = True,
) -> List[Dict[str, Any]]:
    """
    Build a simple linear attack path sequence from confirmed findings:
      1. Reads all finding records from the shared state where verified == 'confirmed'.
      2. Sorts findings:
         - First by ptes_phase in fixed order:
           Intelligence Gathering -> Vulnerability Analysis -> Exploitation -> Post-Exploitation
         - Second by timestamp within the same phase (ascending).
      3. Writes the linear sequence into the attack_path table:
         Each record's leads_to_finding_id points to the next finding in sorted order,
         with the final record having leads_to_finding_id = None.

    Purely a sort-and-link operation with no graph search or scoring logic.

    Returns:
      List of created attack path records.
    """
    def _do_build(c: sqlite3.Connection) -> List[Dict[str, Any]]:
        # 1. Fetch confirmed findings
        sql_fetch = "SELECT * FROM findings WHERE verified = 'confirmed';"
        rows = [dict(r) for r in c.execute(sql_fetch).fetchall()]

        # 2. Sort by ptes_phase in fixed order, then by timestamp, then by ID
        def _sort_key(finding: Dict[str, Any]):
            phase_raw = (finding.get("ptes_phase") or "").strip().lower()
            phase_rank = PTES_PHASE_ORDER.get(phase_raw, 999)
            ts = finding.get("timestamp") or ""
            fid = finding.get("id") or 0
            return (phase_rank, ts, fid)

        sorted_findings = sorted(rows, key=_sort_key)

        # 3. Clear existing attack path records if requested
        if clear_existing:
            c.execute("DELETE FROM attack_path;")

        # 4. Insert linear sequence
        attack_path_records: List[Dict[str, Any]] = []
        num_findings = len(sorted_findings)

        for i, finding in enumerate(sorted_findings):
            step = i + 1
            finding_id = finding["id"]
            leads_to = sorted_findings[i + 1]["id"] if i + 1 < num_findings else None

            phase = finding.get("ptes_phase") or "Unknown Phase"
            desc = finding.get("description") or finding.get("type") or ""
            notes = f"Step {step} [{phase}]: {desc}".strip()

            sql_insert = """
                INSERT INTO attack_path (step, finding_id, leads_to_finding_id, notes)
                VALUES (?, ?, ?, ?);
            """
            c.execute(sql_insert, (step, finding_id, leads_to, notes))

            attack_path_records.append({
                "step": step,
                "finding_id": finding_id,
                "leads_to_finding_id": leads_to,
                "notes": notes,
            })

        c.commit()
        return attack_path_records

    if conn is not None:
        return _do_build(conn)
    else:
        with get_connection(db_path) as c:
            return _do_build(c)


# ---------------------------------------------------------------------------
# CLI Utility Interface
# ---------------------------------------------------------------------------

def _main() -> None:
    """Simple CLI interface for manual inspection and administration."""
    parser = argparse.ArgumentParser(description="CyberForge SQLite State Coordination Store")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to SQLite database file")

    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # init
    subparsers.add_parser("init", help="Initialize database schema")

    # add-host
    add_host_parser = subparsers.add_parser("add-host", help="Add a discovered host")
    add_host_parser.add_argument("ip", help="Host IP address")
    add_host_parser.add_argument("--ports", default="[]", help="JSON string of open ports")

    # claim
    claim_parser = subparsers.add_parser("claim", help="Attempt to claim a host")
    claim_parser.add_argument("ip", help="Host IP address")
    claim_parser.add_argument("agent", help="Agent identifier")

    # list-hosts
    subparsers.add_parser("list-hosts", help="List all hosts")

    # list-findings
    subparsers.add_parser("list-findings", help="List all findings")

    # build-attack-path
    subparsers.add_parser("build-attack-path", help="Build linear attack path from confirmed findings")

    # attack-path
    subparsers.add_parser("attack-path", help="Show current attack path")

    args = parser.parse_args()

    if args.command == "init":
        init_db(args.db)
        print(f"[+] Initialized schema in {args.db}")
    elif args.command == "add-host":
        init_db(args.db)
        hid = add_host(args.ip, open_ports=args.ports, db_path=args.db)
        print(f"[+] Added host {hid}")
    elif args.command == "claim":
        init_db(args.db)
        won = claim_host(args.ip, args.agent, db_path=args.db)
        if won:
            print(f"[+] Agent '{args.agent}' successfully claimed {args.ip} (won race)")
        else:
            print(f"[-] Agent '{args.agent}' failed to claim {args.ip} (already claimed or missing)")
    elif args.command == "list-hosts":
        init_db(args.db)
        hosts = list_hosts(db_path=args.db)
        print(json.dumps(hosts, indent=2))
    elif args.command == "list-findings":
        init_db(args.db)
        findings = list_findings(db_path=args.db)
        print(json.dumps(findings, indent=2))
    elif args.command == "build-attack-path":
        init_db(args.db)
        path = build_attack_path(db_path=args.db)
        print(f"[+] Built attack path with {len(path)} steps")
        print(json.dumps(path, indent=2))
    elif args.command == "attack-path":
        init_db(args.db)
        path = get_attack_path(db_path=args.db)
        print(json.dumps(path, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    _main()
