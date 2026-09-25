# Incident Timeline

All times below are UTC unless otherwise noted. Entries reflect captured project telemetry; where evidence does not establish a fact, the timeline does not infer it.

| Time | Event | Evidence / assessment |
|---|---|---|
| 2026-09-17 16:57:19 | External MySQL session established | `root@45.8.17.198`, SSL/TLS, ConnectionId 19 |
| 2026-09-17 16:57–16:58 | Database discovery and destructive activity | Database/table enumeration followed by creation of extortion artifact and multiple `DROP TABLE` operations |
| 2026-09-17 ~16:58:53 | Connection 19 terminates | Approximately 94 seconds after initial connection |
| 2026-09-17 ~18:09 | Additional destructive activity | ConnectionId 58 associated with `root@64.89.163.80`; multiple databases dropped |
| 2026-09-17 18:09:17–18:09:20 | High-impact administrative cluster | `RESET MASTER`, `PURGE BINARY LOGS`, privilege changes, `SHUTDOWN`; ConnectionIds 60–64 |
| Post-incident | Ransom/extortion artifact preserved | `recover_your_data` evidence reviewed read-only before eradication |
| 2026-09-18 ~23:16 local | MDE containment applied | Device isolation used for DFIR containment |
| Recovery phase | Malicious artifact removed | Ransom database removed after evidence preservation |
| Recovery phase | Corporate database restored | Known-good synthetic data script used |
| Recovery validation | Row counts confirmed | credentials 372; customers 1000; orders 1963; payments 1963 |
| Detection engineering | Destructive SQL detection tuned | Raw events aggregated, auth-enriched, then corrected for ConnectionId reuse with temporal correlation |
| Detection engineering | High-impact admin detection created | Five distinct high-impact operations clustered in a five-minute window |
| Detection engineering | External privileged-auth detection created | Explicit external `root` connections aggregated by source IP |
| Hardened validation | Original exposure path removed | Allow-all NSG removed, firewall restored, `root@'%'` removed |
| Controlled validation | Detection pipeline tested | Four local test-table drops generated expected destructive-activity telemetry and Sentinel incident |

## Evidentiary Boundaries

- A MySQL `Connect` record alone was not treated as proof of compromise unless it contained explicit user/source context and/or correlated query activity.
- Network LogonSuccess telemetry was not automatically labeled interactive RDP compromise.
- The ransom note's claim that data was backed up/downloaded was **not** treated as proof of exfiltration.
- Known cyber-range/Josh Madakor simulation artifacts were excluded from external-attacker attribution.
- No MDE telemetry showed `mysqld.exe` spawning Windows child processes; host-level code execution through MySQL was therefore not claimed.
