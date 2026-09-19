# Investigation Report — Case LAB-C2-001

## 1. Executive Summary

On 2026-08-11, an authorized simulated intrusion was conducted in an isolated home lab. A Meterpreter reverse-TCP payload (`Test.pdf.exe`), disguised with a double file extension, was delivered to a Windows 10 endpoint (`windows10-victim`) and executed by the simulated user. The payload established a command-and-control (C2) connection back to an attacker-controlled host (Kali, `192.168.100.10:4444`) and spawned an interactive shell. Sysmon captured the attack chain and forwarded it to Wazuh, but no matching default Wazuh alert was identified in wazuh-alerts-* during the scoped investigation — the telemetry existed only in raw archives, not in the alert feed. A custom rule was developed to detect the double-extension execution pattern. Validation of the resulting Wazuh alert is pending.

## 2. Case Details

| Field | Value |
|---|---|
| Case ID | LAB-C2-001 |
| Environment | Isolated home lab (VirtualBox, NAT network) |
| Affected host | windows10-victim (192.168.100.30) |
| Attacker host | Kali Linux (192.168.100.10) |
| Detection stack | Wazuh 4.9 + Sysmon (SwiftOnSecurity config) |
| Analyst | Yun Pwint Phyu Linn |
| Date of activity | 2026-08-11 |

## 3. Timeline

| Time shown in evidence | Source | Finding |
| --- | --- | --- |
| Before recorded events | Operator action | File manually downloaded in a Windows browser |
| `2026-08-11 11:55:07.420 UTC` | Sysmon Event ID 1 | `Test.pdf.exe` executed from `C:\Users\yunpwint\Downloads\Test.pdf.exe` |
| `2026-08-11 12:07:48.409 UTC` | Sysmon Event ID 3 | `Test.pdf.exe` connected to `192.168.100.10:4444` |
| `2026-08-11 12:08:06.035 UTC` | Sysmon Event ID 1 | `Test.pdf.exe` spawned `cmd.exe` |

## 4. Technical Findings

### 4.1 Execution
`Test.pdf.exe`, a Meterpreter reverse-TCP payload built with `msfvenom`, was launched from the user's Downloads folder by `explorer.exe` (i.e., double-clicked by the user), consistent with a masquerading/social-engineering delivery scenario.

- File hash (MD5): `31C3ECDD2CCE10B1B6F88F9EC36C5D8D`
- ProcessGuid: `9baae5b7-0d9b-6a7b-cd01-000000001d00`
- Integrity level: Medium (standard user context, not elevated)

### 4.2 Process Tree
```
explorer.exe
└── Test.pdf.exe   (ProcessGuid: 9baae5b7-0d9b-6a7b-cd01-000000001d00)
    └── cmd.exe     (ProcessGuid: 9baae5b7-10a6-6a7b-3c02-000000001d00)
```

### 4.3 Command and Control
The payload established an outbound TCP connection to `192.168.100.10:4444`, matching the attacker's Metasploit handler (`exploit/multi/handler`, payload `windows/x64/meterpreter_reverse_tcp`). 

### 4.4 Detection Gap
Sysmon telemetry confirmed the execution of Test.pdf.exe (Event ID 1), its outbound TCP connection to 192.168.100.10:4444 (Event ID 3), and the subsequent creation of a cmd.exe child process (Event ID 1). These events were retained in wazuh-archives-*.

However, no matching default Wazuh alert was identified in wazuh-alerts-* within the scoped timeframe and queries used during the investigation. This demonstrates the central finding of the exercise: telemetry visibility does not automatically equal detection. Although the underlying activity was visible in the archived logs, a detection rule was still required to evaluate the behavior and generate an actionable alert.

No Sysmon Event ID 11 was recovered for the original file path:

C:\Users\yunpwint\Downloads\Test.pdf.exe

Therefore, the browser-download stage is documented as an operator-observed action rather than a Sysmon-confirmed event. The absence of Event ID 11 does not prove that the download did not occur; it only means that the corresponding file-creation telemetry was not available in the retained evidence.
## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
Defense Evasion | Double File Extension | T1036.007 | Filename `Test.pdf.exe` |
| Execution | User Execution | T1204.002 | Sysmon Event ID 1, launched via `explorer.exe` |
| Execution | Windows Command Shell | T1059.003 | Payload spawned `cmd.exe` |
| Command and Control | Non-standard port | T1571 | Sysmon Event ID 3, outbound to port 4444 |
| Command and Control | Ingress Tool Transfer | T1105 | Payload delivered via HTTP from Kali |

## 6. Remediation: Custom Detection Rule

A custom Wazuh rule (ID `100100`, severity level 10) was created to flag any process created from a path containing `\Downloads\` with a filename matching a misleading double extension pattern (e.g. `*.pdf.exe`), scoped to Sysmon process-creation events (`sysmon_event1`).

## 7. Verdict

**Confirmed suspicious activity — authorized simulation.** Raw Sysmon telemetry confirmed execution of `Test.pdf.exe`, an outbound connection to the Kali C2 listener, and a spawned interactive shell. Wazuh's default rules did not generate a corresponding alert for any of this; the custom rule described above will close that specific gap. “rule developed; validation pending”
