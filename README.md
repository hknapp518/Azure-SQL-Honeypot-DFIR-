# Azure SQL Honeypot — Detection Engineering & DFIR

An Azure security project designed to capture, detect, investigate, and respond to real-world attacks against an intentionally exposed Windows/MySQL honeypot.

The environment integrates Microsoft Defender for Endpoint, Microsoft Sentinel, Azure Monitor Agent, Log Analytics, custom MySQL telemetry, and KQL analytics rules to provide visibility across endpoint authentication, network activity, and database-level attacker behavior.

> **Objective:** Observe what happens after an attacker discovers an exposed system, reconstruct the attack using telemetry, convert observed behavior into detections, and harden the environment based on the findings.

<img width="1536" height="1024" alt="Azure SQL Honeypot Architecture" src="https://github.com/user-attachments/assets/74d1c6a7-3e0a-49f8-86dc-4aa891f1eaa7" />

---

## Project Status

- [x] **Phase 1** — Windows honeypot deployed
- [x] **Phase 2** — MySQL deployed and populated with synthetic corporate data
- [x] **Phase 3** — MySQL telemetry ingested into Log Analytics
- [x] **Phase 4** — Sentinel detections deployed and validated
- [x] **Phase 5** — Controlled 12-hour exposure
- [x] **Phase 6** — Breach detected
- [x] **Phase 7** — Threat hunting and investigation
- [x] **Phase 8** — Containment
- [x] **Phase 9** — Eradication and recovery
- [x] **Phase 10** — DFIR reporting

---

## Architecture

The lab was designed as an intentionally vulnerable Azure workload with multiple telemetry sources feeding a centralized Log Analytics workspace and Microsoft Sentinel.

### Security Stack

| Component | Purpose |
|---|---|
| Azure VM | Windows honeypot host |
| MySQL | Internet-targeted database containing synthetic data |
| Network Security Group | Controlled network exposure |
| Microsoft Defender for Endpoint | Endpoint telemetry and investigation |
| Azure Monitor Agent | Log collection |
| Log Analytics Workspace | Centralized telemetry repository |
| Microsoft Sentinel | SIEM, threat hunting, alerting, and investigation |
| `MySQLAudit_CL` | Custom database query/activity telemetry |
| KQL | Threat hunting and detection engineering |

---

## Attack Scenario

The honeypot contained **synthetic corporate data only**, including simulated employee and financial records.

The system was intentionally configured with weakened security controls during the observation phase to determine how an external attacker would discover and interact with the environment.

During the exposure window, an attacker successfully compromised the MySQL root account.

The attacker subsequently:

1. Successfully authenticated to the database.
2. Enumerated available databases and tables.
3. Accessed the synthetic database structure.
4. Executed destructive SQL commands.
5. Deleted database tables.
6. Created a ransom message demanding cryptocurrency payment.

Because MySQL query telemetry was being collected, the investigation provided visibility beyond the successful authentication event.

The database logs showed the actual SQL activity performed by the attacker.

### Key DFIR Finding

The ransom message implied that the database had been encrypted.

Telemetry demonstrated that this was **not what occurred**.

The attacker had issued destructive SQL commands that removed the underlying data. This distinction was visible through the captured MySQL query logs and demonstrates why authentication telemetry alone is insufficient when investigating database compromise.

---

## Detection Engineering

One of the primary goals of the project was to convert observed attacker behavior into reusable detections.

Instead of stopping after identifying the compromise, KQL analytics were developed around behaviors observed during the incident.

### Detection 1 — Brute Force Followed by Successful Authentication

**Purpose:** Identify repeated failed authentication attempts followed by a successful login.

**Severity:** High

**MITRE ATT&CK:** Credential Access / Brute Force

---

### Detection 2 — Destructive Database Activity

**Purpose:** Identify rapid deletion of multiple database objects.

Example logic:

`3+ destructive table operations within 3 minutes`

This behavior would be highly unusual during normal database operation and may indicate destructive attacker activity.

**Severity:** High

---

### Detection 3 — Suspicious SQL Commands

Monitors database telemetry for potentially dangerous commands such as:

- `DROP`
- `DELETE`
- `ALTER`

The detection provides visibility into unusual database modification activity and can be correlated with authentication and endpoint telemetry during an investigation.

---

## Investigation Workflow

The incident was investigated across multiple telemetry sources rather than treating individual alerts independently.

**Authentication → Endpoint → Network → Database → Sentinel correlation**

KQL was used to answer questions such as:

- Which accounts were targeted?
- Did authentication eventually succeed?
- What activity occurred after authentication?
- What SQL commands were executed?
- Were database objects modified or deleted?
- Did the endpoint exhibit additional suspicious activity?
- Was the activity isolated to the honeypot?
- What indicators should become future detections?

---

## Incident Response

### Identification

Sentinel and Log Analytics telemetry identified suspicious authentication and database activity.

### Containment

The compromised system was isolated and external exposure was removed.

### Eradication

Weak credentials and intentionally vulnerable configurations used during the honeypot phase were removed.

### Recovery

The environment was rebuilt/hardened and security controls were reviewed before restoring normal connectivity.

### Lessons Learned

The investigation demonstrated that detecting the successful login alone would not have explained the full incident.

Database-level telemetry revealed what the attacker actually did **after gaining access**.

That finding drove additional Sentinel detection engineering and informed the hardening phase.

---

## Hardening

Following the investigation, the environment moved from intentionally vulnerable to hardened.

Changes included:

- Restricting unnecessary inbound access
- Removing broad RDP exposure
- Strengthening authentication controls
- Applying least-privilege principles
- Reviewing NSG rules
- Maintaining Defender monitoring
- Retaining MySQL audit telemetry
- Deploying detections derived from observed attacker behavior
- Documenting indicators, findings, and remediation actions

---

## Skills Demonstrated

This project demonstrates hands-on experience with:

**Microsoft Sentinel • Microsoft Defender for Endpoint • Azure • Log Analytics • KQL • SIEM • DFIR • Threat Hunting • Detection Engineering • Incident Response • MySQL Security • Vulnerability Remediation • Network Security • MITRE ATT&CK**

---

## Key Takeaway

The objective of this project was not simply to expose a vulnerable VM and collect attacks.

The project followed the security lifecycle from:

**Exposure → Telemetry → Detection → Investigation → Containment → Eradication → Recovery → Detection Improvement**

The most significant finding was that database-level telemetry revealed attacker behavior that would have been missed by relying solely on authentication or endpoint alerts.

The observed attack was then used to improve detections and harden the environment, turning a honeypot experiment into an end-to-end detection engineering and DFIR exercise.
