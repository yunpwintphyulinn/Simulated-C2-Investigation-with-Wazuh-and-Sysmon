# Simulated-C2-Investigation-with-Wazuh-and-Sysmon

An authorized home-lab project that simulates a Meterpreter reverse-TCP intrusion against a Windows 10 endpoint and investigates the resulting telemetry using Sysmon and Wazuh. The investigation correlates process creation, an outbound C2 callback, and child-shell execution through Sysmon Event IDs 1 and 3.

The project also demonstrates the difference between telemetry visibility and alert generation: the simulated activity was retained in `wazuh-archives-*`, but no matching default Wazuh alert was identified during the scoped investigation. To improve detection coverage, a custom Wazuh rule was developed to identify double-extension executables, such as `Test.pdf.exe`, launched from a user’s Downloads directory.

The custom rule addresses the masquerading and payload-execution stage of the attack chain, while the C2 callback is investigated through raw Sysmon network telemetry.

> **Disclaimer:** This is an isolated, authorized home lab. All activity was performed against VMs owned and controlled by the author, on a “VirtualBox NAT Network”. No real-world systems were targeted. The generated payload is a standard Metasploit test payload used purely to produce realistic attacker telemetry for detection engineering practice.

> **Disclaimer:** Timestamp discrepancy: : Sysmon UtcTime records endpoint event time, while the Wazuh dashboard @timestamp reflects later ingestion after the server became available. The investigation timeline therefore uses Sysmon UtcTime.

## 1. Objective

- Build a small "purple team" lab: attacker (Kali) → victim (Windows 10) → detection stack (Wazuh + Sysmon on Ubuntu).
- Learn how attacker activity actually shows up as telemetry (process creation, file creation, network connections).
- Confirm that raw telemetry can exist in a SIEM (`wazuh-archives-*`) **without** producing an alert (`wazuh-alerts-*`) — i.e. a detection gap — and then close that gap with a custom Wazuh rule.
- Practice SOC-analyst workflow: reconstruct a process tree, correlate multiple Sysmon event IDs, map to MITRE ATT&CK, and write up findings.

## 2. Lab Architecture

| Role | OS | IP | Specs |
|---|---|---|---|
| Wazuh Manager / Indexer / Dashboard | Ubuntu 24.04 Desktop | 192.168.100.20 | 16 GB RAM, 4 vCPU, 100 GB disk |
| Attacker | Kali Linux | 192.168.100.10 | 4 GB RAM, 2 vCPU, 80 GB disk |
| Victim (monitored endpoint) | Windows 10 | 192.168.100.30 | 4 GB RAM, 4 vCPU, 80 GB disk |

All three VMs are on the same VirtualBox NAT Network (`SOC-HomeLab-Net`) VirtualBox network so they can reach each other.

See [***Lab topology***](environment/1-Lab-topology.png) for the diagram and connectivity notes.

## 3. Tooling

- **VirtualBox** — hypervisor for all three VMs
- **Wazuh 4.9** (manager, indexer, dashboard, agent) — SIEM / detection stack
- **Sysmon** (SwiftOnSecurity config) — Windows endpoint telemetry
- **Metasploit Framework** (`msfvenom`, `msfconsole`) — payload generation and C2 handler
- **Nmap** — service discovery against the victim

## 4. Setup Summary and Troubleshooting

Full step-by-step commands are in 
[***Setup***](docs/setup-and-controlled-simulation.md)
[***Troubleshooting***](docs/troubleshooting.md) 

## 5. Attack Simulation Summary

| Item | Value |
|---|---|
| Case ID | LAB-C2-001 |
| Payload | `windows/x64/meterpreter_reverse_tcp` |
| Filename (delivered) | `Test.pdf.exe` |
| Delivery method | Manually downloaded through a web browser on the Windows 10 VM from the Kali HTTP server (hxxp://192[.]168[.]100[.]10:9999/) |
| C2 listener | Kali, port 4444 |
| Windows agent name | `windows10-victim` |
| Execution time | 2026-08-11 11:55:07.420 UTC |

## 6. Evidence timeline

The timeline below uses the `UtcTime` values. The manual browser download occurred before the recorded Sysmon events, but its exact time was not captured.

| Time shown in evidence | Event | Finding |
| --- | --- | --- |
| `2026-08-11 11:55:07.420 UTC` | Sysmon Event ID 1 | `Test.pdf.exe` executed from Downloads; parent was `explorer.exe` |
| `2026-08-11 12:07:48.409 UTC` | Sysmon Event ID 3 | `Test.pdf.exe` connected to `192.168.100.10:4444` |
| `2026-08-11 12:08:06.035 UTC` | Sysmon Event ID 1 | `Test.pdf.exe` spawned `cmd.exe` |


## 7. Key Finding: Detection Gap

Sysmon captured the observed execution chain: Test.pdf.exe executed from the Downloads folder, initiated an outbound connection to the Kali lab host on TCP 4444, and spawned cmd.exe. These events were retained in wazuh-archives-*. However, no original Sysmon file-creation event for C:\Users\yunpwint\Downloads\Test.pdf.exe was recovered, so the browser-download stage is documented as operator-observed rather than Sysmon-confirmed. No matching default Wazuh alert was identified during the investigation.

## 8. Custom Detection Rule

To close the gap, a custom rule was written to flag any executable using a misleading double extension (e.g. `.pdf.exe`) launched from a user's `Downloads` folder — mapped to **MITRE ATT&CK T1036 (Masquerading)**.

[***Rule File***](rules/rules.xml)
[***Design Note***](docs/detection-rule.md)

## 9. Repository Structure

```
Simulated-C2-Investigation-with-Wazuh-and-Sysmon/
├── README.md
├── LICENSE
├── docs/
│   ├── detection-rule.md
│   ├── investigation-notes.md
│   ├── investigation-report.md
│   ├── setup-and-controlled-simulation.md
│   └── troubleshooting.md
├── environment/
│   └── 1-Lab-topology.png
├── evidence/
│   ├── 1-Lab-topology.png
│   ├── 2-Wazuh-agent-active.png
│   ├── 3-Payload-execution-EventID1.png
│   ├── 4-Child-shell-EventID1.png
│   ├── 5-Network-callback-EventID3.png
│   └── 6-Custom-Wazuh-rule.png
└── rules/
    └── rules.xml                 
```
## 10. Skills Demonstrated

- SIEM deployment and troubleshooting (Wazuh manager/indexer/dashboard, agent enrollment)
- Endpoint telemetry engineering (Sysmon configuration, log forwarding via `ossec.conf`)
- Offensive tooling fundamentals (`msfvenom`, `msfconsole`, `nmap`) for generating realistic attacker telemetry
- Log analysis and event correlation across Sysmon Event IDs 1 and 3.
- Process-tree reconstruction using `ProcessGuid` / `ParentProcessGuid`
- Detection engineering: identifying a coverage gap and writing a custom Wazuh rule
- MITRE ATT&CK mapping
- Incident documentation / report writing

---
*Built with the assistance of AI tools (ChatGPT and Claude) for structuring, documentation, and troubleshooting.*

