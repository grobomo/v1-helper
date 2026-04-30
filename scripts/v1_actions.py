"""
v1_actions.py — DEPRECATED. Use scripts/automate/ sub-module instead.

Kept for backward compatibility with executor.py imports.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from automate.js import check_cve as _check, click_status_dropdown as _status_dd, select_status as _sel


def build_dismiss_cve_js(cve_id):
    return _check(cve_id)

def build_change_status_js(status):
    return _sel(status)

def build_bulk_action_sequence(cve_ids, status):
    steps = [(f"Select {c}", _check(c)) for c in cve_ids]
    steps.append((f"Change status to {status}", _sel(status)))
    return steps
