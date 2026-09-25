# DFIR Incident Report — Azure MySQL Honeypot

## Executive Summary

An intentionally exposed Windows/MySQL workload in an Azure cyber range experienced unauthorized privileged MySQL access followed by destructive database-extortion activity. Custom MySQL audit telemetry captured external `root` connections, database enumeration, destructive SQL, extortion artifacts, and a later cluster of high-impact administrative operations.

The incident was investigated using Microsoft Sentinel, Log Analytics, Microsoft Defender for Endpoint, and MySQL telemetry. The host was contained, the malicious database artifact was preserved and then eradicated, the synthetic corporate database was restored, and the original vulnerable access path was hardened. Observed behaviors were subsequently converted into new Sentinel analytics and validated against historical telemetry and controlled test activity.

## Scope

**Asset:** `CORP-DB-PROD02`  
**Database:** MySQL 8  
**SIEM:** Microsoft Sentinel  
**Endpoint telemetry:** Microsoft Defender for Endpoint  
**Database telemetry:** `MySQLAudit_CL`  
**Data classification:** Synthetic lab data only

## Confirmed Findings

### Unauthorized privileged database access

Telemetry captured external MySQL sessions using the `root` account. A high-confidence destructive session was associated with `45.8.17.198` (ConnectionId 19).

### Destructive database activity

ConnectionId 19 enumerated database objects, created an extortion-related artifact, and dropped the synthetic corporate tables `orders`, `credentials`, `customers`, and `payments`. Additional destructive activity affected other lab databases.

A later sequence included multiple database drops followed by `RESET MASTER`, `PURGE BINARY LOGS`, privilege changes, and `SHUTDOWN`.

### Extortion artifact

A `RECOVER_YOUR_DATA` artifact contained a cryptocurrency-payment demand and claimed the data had been backed up. The note was preserved as evidence.

**Important limitation:** the attacker's statement is not proof of exfiltration. This investigation does not claim that data left the environment.

### Endpoint scoping

A focused MDE hunt did not identify `mysqld.exe` spawning Windows child processes. Known cyber-range simulation artifacts were excluded from attacker attribution.

## Incident Classification

The strongest evidence supports **unauthorized privileged database access followed by destructive SQL/extortion activity**.

**MITRE ATT&CK:** T1485 — Data Destruction is supported by the observed deletion behavior. Data Encrypted for Impact is not claimed because encryption was not observed.

## Response Actions

### Containment
- Isolated the device through Microsoft Defender for Endpoint.
- Removed broad network exposure.

### Eradication
- Preserved the extortion artifact before removal.
- Removed the attacker-created ransom database.
- Removed remote `root@'%'` access.
- Restored Windows Defender Firewall.
- Removed the custom allow-all inbound NSG rule.

### Recovery
- Restored `corp_db_prod02` from a known-good synthetic-data build script.
- Validated recovered table counts:
  - credentials: 372
  - customers: 1,000
  - orders: 1,963
  - payments: 1,963

## Detection Improvements

Three incident-derived analytics were added:

1. **MySQL Mass Destructive Database Activity** — detects bursts of destructive table/database operations and enriches them with temporally related authentication context.
2. **MySQL High-Impact Administrative Activity** — detects clusters of binary-log manipulation, privilege changes, and shutdown behavior.
3. **External Privileged MySQL Authentication** — detects explicit external `root` connections and aggregates them by source.

During tuning, MySQL ConnectionId reuse was found to cause stale authentication attribution. The destructive-activity rule was corrected by requiring the authentication event to occur before the destructive activity and within a 30-minute correlation window.

## Validation

The destructive rule was validated using historical incident telemetry and a controlled local database containing four test tables. The test generated four `DROP TABLE` records in `MySQLAudit_CL` and the scheduled Sentinel rule generated the expected high-severity incident.

The hardened environment retained telemetry while removing the original remote privileged access path.

## SOAR Design Note

A Logic Apps/Sentinel response playbook was attempted but could not be deployed because the cyber-range identity lacked `Microsoft.Logic/workflows/write` and `Microsoft.Web/connections/write`. The automation is therefore documented as a design/attempt, not as a deployed response capability.

## Conclusion

The project demonstrated the value of correlating database telemetry with endpoint and SIEM data. Authentication alerts identified access, but database audit logs established what happened after access. Those findings directly informed containment, recovery, hardening, and new detection logic.
