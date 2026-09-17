# Pre-Exposure Baseline Results

## Purpose

A 24-hour baseline was collected from `CORP-DB-PROD02` before the honeypot entered the controlled exposure phase.

The baseline establishes normal endpoint, authentication, network, and MySQL activity before security controls are intentionally weakened.

## Baseline Results

| Metric | Pre-Exposure Result |
|---|---:|
| Process Executions | 1,285 |
| Unique Processes | 166 |
| Network Events | 3,091 |
| Unique Network Remote IPs | 1,115 |
| Total Logon Events | 137 |
| Successful Logons | 23 |
| Failed Logons | 102 |
| Unique Logon Remote IPs | 6 |
| MySQL Events | 26 |

## MySQL Observation Window

- **First observed event:** September 16, 2026 9:21:35 PM
- **Last observed event:** September 17, 2026 10:40:06 AM
- **Events observed:** 26

## Endpoint Health

Microsoft Defender for Endpoint was validated before exposure:

- **Device:** `CORP-DB-PROD02`
- **Operating System:** Windows 11
- **Onboarding Status:** Onboarded
- **Sensor Health:** Active

## Network Baseline Note

The 1,115 unique remote IP addresses represent raw `DeviceNetworkEvents`
telemetry and should not be interpreted as 1,115 external attackers.

Review of the most frequently observed connections identified Azure platform
traffic, private network communication, Azure Monitor activity, and normal
application traffic. Attack-source metrics will therefore be calculated
separately during the controlled exposure and DFIR phases.

## Baseline Conclusion

The pre-exposure baseline confirms that endpoint, authentication, network,
and MySQL telemetry were being collected before intentional exposure.

These measurements will be used as the reference point for comparing
activity observed during compromise and after remediation.
