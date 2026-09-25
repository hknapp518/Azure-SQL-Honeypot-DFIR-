# Azure Ransomware Honeypot | DFIR & Detection Engineering

> **Vulnerable Azure workload → ransomware/extortion attack → DFIR → Sentinel detections → hardened validation**

I intentionally exposed an Azure Windows/MySQL workload to measure real-world attack activity. External infrastructure gained privileged MySQL access, executed destructive SQL, destroyed synthetic corporate data, and deployed a cryptocurrency ransom artifact.

I reconstructed the incident, contained and recovered the workload, hardened the original attack path, and converted observed attacker behavior into **3 new Microsoft Sentinel detections**.

**Stack:** Microsoft Sentinel • Defender for Endpoint • Azure • Log Analytics • AMA/DCR • KQL • MySQL

## Incident at a Glance

| | Evidence-backed result |
|---|---|
| **Attack Surface** | **10 Windows remote IPs** + **13 external MySQL source IPs** observed |
| **Authentication** | **239 failed Windows logons** + **73 failed MySQL authentications** |
| **Compromise** | **112 external MySQL root connections** captured |
| **Ransomware Attack** | **34 destructive SQL operations** + `RECOVER_YOUR_DATA` ransom artifact |
| **Impact** | Corporate database **destroyed** + **5 high-impact admin operations in ~3 seconds** |
| **Detection Engineering** | **3 new Sentinel analytics** engineered and validated |
| **Hardening Result** | **0 Windows logons**, **0 uncontrolled destructive SQL**, remote `root@'%'` **removed** |
| **Recovery** | **5,298 synthetic records restored** across 4 corporate tables |

> The ransom note claimed the data had been backed up/downloaded. Telemetry did **not** prove exfiltration, so I do not claim it occurred.

---

## Architecture & Attack Path

<img width="1774" height="887" alt="Azure ransomware honeypot architecture and attack flow" src="https://github.com/user-attachments/assets/c24df1bb-242f-4ad6-8416-978a0430a500" />

**Intentional exposure:** broad inbound NSG access, Windows Firewall disabled, MySQL exposed on TCP/3306, and remote `root@'%'` authentication enabled.

**Hardened state:** broad inbound exposure removed, Windows Firewall restored, remote MySQL root eliminated, database recovered, and behavior-based detections deployed.

**Authentication telemetry showed access occurred. Database telemetry showed what the attacker actually did after access.**

---

## Vulnerable vs. Hardened Security Outcomes

| Security Metric | 🔴 Vulnerable Exposure | 🟢 Hardened Validation | Security Outcome |
|---|---:|---:|---|
| **Windows logon events** | **307** | **0** | No Windows logon activity observed |
| **Failed Windows logons** | **239** | **0** | Authentication noise absent in validation |
| **Successful Windows logons** | **47** | **0** | No successful Windows logons observed |
| **Unique Windows remote IPs** | **10** | **0 observed** | Remote authentication activity absent |
| **MySQL audit events** | **1,562** | **12** | Telemetry remained operational after hardening |
| **Failed MySQL authentications** | **73** | **0 observed*** | No failed MySQL authentication observed |
| **Successful external MySQL connections** | **152** | **0 expected by hardened design*** | External privileged path removed |
| **External root connections** | **112** | **0 expected by hardened design*** | Remote root eliminated |
| **Unique external MySQL source IPs** | **13** | **0 expected by hardened design*** | Internet-sourced MySQL access removed |
| **Destructive SQL operations** | **34** | **0 uncontrolled** | No destructive attacker activity observed |
| **High-impact MySQL admin operations** | **5** | **0 observed** | Destructive admin sequence absent |
| **Database destruction** | **Yes** | **No** | Database restored and remained intact |
| **Allow-all inbound NSG** | **Enabled** | **Removed** | Attack surface reduced |
| **Windows Firewall** | **Disabled** | **All profiles enabled** | Host firewall restored |
| **MySQL privileged account** | `root@'%'` | `root@localhost` only | Remote privileged authentication removed |

> **Measurement scope:** vulnerable-side counts come from the defined exposure query window; hardened-side counts come from the captured post-hardening validation window. They are not equal-duration traffic-rate comparisons. The **34 destructive operations** are the time-bounded exposure metric; the broader historical hunt identified **40 destructive SQL events**.

> \* Hardened MySQL remote-access outcomes are supported by removal of `root@'%'`, retention of `root@localhost`, removal of the allow-all inbound NSG rule, and restoration of Windows Firewall.

---

## Incident Reconstruction

At approximately **2026-09-17 16:57:19 UTC**, `root@45.8.17.198` established an SSL/TLS MySQL session as **ConnectionId 19**. Within roughly **94 seconds**, the session enumerated database objects, created an extortion artifact, inserted a cryptocurrency ransom message, and dropped the synthetic corporate tables `orders`, `credentials`, `customers`, and `payments`.

Later telemetry captured a rapid administrative sequence:

```text
RESET MASTER
PURGE BINARY LOGS ...
REVOKE ALL PRIVILEGES, GRANT OPTION FROM root@'%'
GRANT SHUTDOWN ON *.* TO root@'%'
SHUTDOWN
```

The destructive activity supports **MITRE ATT&CK T1485 — Data Destruction**. Encryption was not observed. A focused MDE hunt also found **no `mysqld.exe` child-process execution**, keeping the defensible compromise chain to:

**Internet → privileged MySQL access → destructive SQL → database extortion**

For the full chronology, see the **[attack timeline](timeline/attack-timeline.md)** and **[incident report](report/incident-report.md)**.

---

## Detection Engineering

The original monitoring emphasized authentication. DFIR showed the highest-impact behavior occurred **after authentication**, so I converted the incident into three behavior-based analytics.

| Detection | What it detects | Validation |
|---|---|---|
| **[MySQL Mass Destructive Database Activity](detections/mysql-mass-destructive-database-activity.kql)** | Bursts of `DROP TABLE` / `DROP DATABASE` activity | Historical attack + controlled DROP test |
| **[MySQL High-Impact Administrative Activity](detections/mysql-high-impact-administrative-activity.kql)** | Log manipulation, privilege changes, and shutdown behavior | **5 actions in ~3 sec** |
| **[External Privileged MySQL Authentication](detections/mysql-external-privileged-authentication.kql)** | Explicit external `root` sessions aggregated by source | Repeated privileged connections observed |

### Detection tuning that mattered

The initial destructive-SQL hunt returned **40 events**. I aggregated activity by ConnectionId, required **3+ destructive operations in five minutes**, and enriched sessions with authentication context.

MySQL **reuses ConnectionIds**, which initially allowed later legitimate activity to inherit an older attacker IP. I corrected the correlation by requiring authentication to occur **before the destructive activity and within 30 minutes**.

**Raw events → session aggregation → auth enrichment → ConnectionId reuse discovered → temporal correlation → validated attribution**

> **Engineering lesson:** a rule that fires but attributes the wrong source is not a finished detection.

### End-to-End Validation

The destructive rule was safely validated against a disposable local database using four controlled `DROP TABLE` operations:

**Workbench → MySQL general log → AMA/DCR → `MySQLAudit_CL` → Sentinel analytics → High-severity incident**

The observed test-to-incident interval was approximately **9 minutes**, including ingestion, scheduled-rule execution, and Sentinel processing. This is a captured validation measurement—not a universal MTTD claim.

---

## Containment, Recovery & Hardening

After confirming destructive activity, I:

- isolated the host through **Microsoft Defender for Endpoint**;
- removed the broad allow-all NSG exposure;
- restored **Windows Defender Firewall**;
- preserved and then removed the attacker-created ransom database;
- removed remote `root@'%'` and retained `root@localhost`;
- restored `corp_db_prod02` from a known-good synthetic-data script;
- validated **5,298 restored records**.

| Restored table | Rows |
|---|---:|
| `credentials` | 372 |
| `customers` | 1,000 |
| `orders` | 1,963 |
| `payments` | 1,963 |

SOAR containment was designed but **not represented as implemented**: cyber-range RBAC blocked the required Logic App and API-connection write permissions.

---

## Reproduce the Lab

The project can be reproduced at a high level without recreating the destructive Internet activity:

1. Deploy an Azure Windows VM and install MySQL with synthetic data.
2. Enable MySQL general/audit logging and onboard the endpoint to Defender for Endpoint.
3. Configure **AMA/DCR → Log Analytics** ingestion for Windows, endpoint, network, and MySQL telemetry.
4. Enable Microsoft Sentinel and deploy the KQL analytics from **[`detections/`](detections/)**.
5. Generate controlled benign authentication and disposable-database test events.
6. Validate **source → telemetry → analytics rule → Sentinel incident**.
7. Apply the hardened controls and confirm telemetry/detections remain operational.

> Destructive behavior in this project was observed in an authorized cyber range. Reproduction should use controlled test data and disposable resources.

---

## Engineering Artifacts

- **[Attack timeline](timeline/attack-timeline.md)** — incident chronology and key attacker actions
- **[Incident report](report/incident-report.md)** — formal findings, response, and lessons learned
- **[Mass destructive SQL detection](detections/mysql-mass-destructive-database-activity.kql)**
- **[High-impact administrative activity detection](detections/mysql-high-impact-administrative-activity.kql)**
- **[External privileged MySQL authentication detection](detections/mysql-external-privileged-authentication.kql)**

### What This Project Demonstrates

**DFIR:** evidence preservation, scoping, reconstruction, containment, eradication, recovery  
**Detection Engineering:** KQL, behavioral analytics, temporal correlation, tuning, false-positive analysis, validation  
**Telemetry Engineering:** MySQL logs → AMA/DCR → Log Analytics → Sentinel  
**Threat Hunting:** authentication, database, endpoint, process, and network correlation  
**Azure Security:** NSG hardening, Defender for Endpoint, Sentinel, Log Analytics

### Lessons Learned

- **Access is not impact.** Authentication alerts did not explain what happened after compromise; SQL telemetry did.
- **Telemetry quality drives DFIR quality.** Custom database logging made the destructive sequence reconstructable.
- **Detection tuning is engineering.** ConnectionId reuse required temporal correlation, not another keyword.
- **Ransom notes are attacker claims, not evidence.** The cryptocurrency/extortion artifact was real; exfiltration was not proven.
- **Incidents should improve controls.** Observed attacker behavior became new detections and the original attack path was hardened.

---

## Disclaimer

This project was performed in an authorized cyber-range/lab using synthetic data for defensive security research and portfolio development. External indicators are documented only as observed telemetry. No offensive activity was directed at third-party systems.
