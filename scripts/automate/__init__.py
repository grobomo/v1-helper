"""
v1-helper/automate — V1 console automation via Blueprint MCP action plans.

Generates structured action plans (JSON) that Claude Code executes step-by-step
using Blueprint MCP browser tools. Plans include JS payloads, navigation targets,
verification snapshots, and expected outcomes.

Modules:
  actions  — High-level plan builders (dismiss CVEs, change status, bulk ops)
  js       — JavaScript payloads for V1 DOM interaction
  reader   — V1 page detection and data scraping
  overlay  — Analysis badge injection into V1 console
"""

from .actions import (
    plan_dismiss_cves,
    plan_change_cve_status,
    plan_inject_overlays,
    plan_read_page,
    plan_from_report,
    V1_PAGES,
)
