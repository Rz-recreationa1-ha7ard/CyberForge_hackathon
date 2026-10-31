"""
attack_path.py - Linear Attack Path Builder for Confirmed Security Findings.

Designed for authorized hackathon/CTF exercises against organizer-provided lab targets.
Sorts confirmed findings by PTES phase and timestamp, linking them into a simple linear sequence:
  Intelligence Gathering -> Vulnerability Analysis -> Exploitation -> Post-Exploitation
"""

from __future__ import annotations

from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Union

import state
from state import PTES_PHASE_ORDER, build_attack_path, get_attack_path, add_attack_path_step

__all__ = [
    "PTES_PHASE_ORDER",
    "build_attack_path",
    "get_attack_path",
    "add_attack_path_step",
]

