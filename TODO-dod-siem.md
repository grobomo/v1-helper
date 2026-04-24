# DoD SIEM Event ID Verification - Panavision

## Context
- Document: `Panavision_SIEM_Event_IDs_2026.docx` (from TrendIQ chat)
- TrendIQ: https://trendiq.trendmicro.com/shared/A3D6008D-93C8-4402-A12F-856AA077C91C
- Reference: CISA/NSA/ASD "Priority Logs for SIEM Ingestion" (May 2025)
- Verification script: `scripts/verify_dod_events.py`
- Results: `reports/dod_event_verification.json`

## Verification Results (2026-03-26)

Searched EP tenant V1 XDR (7-day window) for all 71 DoD event IDs using `winEventId:<ID>`.

### Confirmed Present (8)
| EID | Description | Doc Status |
|-----|------------|------------|
| 4104 | Script Block Logging | Standard |
| 4624 | Successful Logon | Standard |
| 4625 | Failed Logon | Standard |
| 4720 | User Account Created | Standard |
| 5857 | WMI Provider Loaded | Standard |
| 5859 | WMI Subscription Event | Standard |
| 5861 | WMI ESS Event Filter | Standard |
| **4769** | **Kerberos Service Ticket** | **Doc says 3P-Log-Collector but found natively** |

### Discrepancies: Doc Says "Standard" but 0 Hits (10)
| EID | Description | Likely Reason |
|-----|------------|---------------|
| 4688 | Process Creation | V1 captures via internal eventId=1, not as winEventId |
| 4656 | Handle to Object Requested | V1 uses eventId=3/4 for file/registry |
| 4657 | Registry Value Modified | Same — V1 internal telemetry |
| 4663 | Object Access Attempt | Same |
| 4670 | Object Permissions Changed | May not have occurred in 7 days |
| 4722 | User Account Enabled | Low frequency event |
| 4725 | User Account Disabled | Low frequency event |
| 4726 | User Account Deleted | Low frequency event |
| 5858 | WMI Provider Error | No errors in 7 days |
| 5860 | WMI Subscription Binding | No bindings in 7 days |

### Key Technical Finding
V1 uses **dual telemetry**:
- Internal `eventId` system (1-11 with sub-IDs) for rich sensor data
- `winEventId` field only on events ingested as raw Windows Security Log entries

The doc's "Covered Standard" claim means V1's agent captures equivalent telemetry — but stored under V1's own schema, **not** as `winEventId` entries. A DoD auditor searching `winEventId:4688` will find 0 results unless the mapping is understood.

### Pending Verification (from doc)
- 4660 (Object Deleted) — 0 hits, still unresolved
- 4689 (Process Termination) — 0 hits, still unresolved
- DNS 277-278 (DNS Analytical) — not testable via endpoint API

### Document Updates Needed
1. Add caveat to "Covered Standard" events explaining V1 internal eventId vs winEventId
2. Update 4769 from "3P-Log-Collector" to "Covered Standard"
3. Resolve pending items (4660, 4689, DNS 277-278)
4. Update Coverage Summary Scorecard percentages

## Panavision Meeting
- Meeting: "Panavision_ SIEM Review" (Feb 23, 2026)
- No local recording found — transcript may be in Teams only
- Need to check via Blueprint MCP what was specifically requested
