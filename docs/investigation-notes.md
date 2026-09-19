# Investigation Notes — LAB-C2-001

Raw evidence and query notes from the Wazuh/Sysmon investigation, in the order they were pulled.

## Detection Gap

All of the above events are present in `wazuh-archives-*`. **No corresponding entry appeared in `wazuh-alerts-*`.** The relevant Sysmon events were present in wazuh-archives-*, but no corresponding alert was identified in wazuh-alerts-* using the investigation queries and timeframe documented below. See ****detection_rule.md**** for the custom rule written to close this gap.


## 1. Find the Payload Execution (Sysmon Event ID 1)

Query (`wazuh-archives-*`):
```
data.win.system.eventID: "1" AND data.win.eventdata.image: *Test.pdf.exe*
```

| Field | Value |
|---|---|
| File path | `C:\Users\yunpwint\Downloads\Test.pdf.exe` |
| UtcTime | `2026-08-11 11:55:07.420` |
| User | `WINDOWSVM\yunpwint` |
| Command line | `"C:\Users\yunpwint\Downloads\Test.pdf.exe"` |
| ProcessGuid | `9baae5b7-0d9b-6a7b-cd01-000000001d00` |
| ParentProcessGuid | `9baae5b7-026a-6a7b-7c00-000000001d00` |
| Parent Image | `C:\Windows\explorer.exe` |
| File hash (MD5) | `31C3ECDD2CCE10B1B6F88F9EC36C5D8D` |
| Integrity level | Medium |

Process tree so far:
```
explorer.exe
└── Test.pdf.exe
```

## 2. Find the Child Shell

Query:
```
data.win.eventdata.parentProcessGuid: "{9baae5b7-0d9b-6a7b-cd01-000000001d00}"
```

Result: `Test.pdf.exe` spawned a `cmd.exe` child process.

```
explorer.exe
└── Test.pdf.exe
    └── cmd.exe   (ProcessGuid: 9baae5b7-10a6-6a7b-3c02-000000001d00)
```
## 3. Check the File-Creation Event (Sysmon Event ID 11)

The file was manually downloaded through the Windows browser. However, no Sysmon Event ID 11 was recovered for the original path:

```text
C:\Users\yunpwint\Downloads\Test.pdf.exe
```

## 4. Check the Network Connection (Sysmon Event ID 3)

Query:
```
data.win.system.eventID: "3" AND data.win.eventdata.processGuid: "{9baae5b7-0d9b-6a7b-cd01-000000001d00}"
```

| Field | Value |
|---|---|
| File manually downloaded through the Windows VM browser from the Kali HTTP server | 
| Destination IP | 192.168.100.10 |
| Destination port | 4444 |
| ProcessGuid | `9baae5b7-0d9b-6a7b-cd01-000000001d00` |
| UtcTime | `2026-08-11 12:07:48.409` |
| Image | `C:\Users\yunpwint\Downloads\Test.pdf.exe` |

## 5. Evidence Correlation Table

| Sysmon Event | Key Evidence | Finding |
|---|---|---|
| Event ID 1 | Image = C:\Users\yunpwint\Downloads\Test.pdf.exe | Payload executed from Downloads |
| Event ID 1 | `cmd.exe` ParentProcessGuid = payload's ProcessGuid | Payload launched a shell |
| Event ID 3 | Same payload ProcessGuid, destination `192.168.100.10:4444` | Payload connected back to Kali (C2 callback) |
| Sysmon Event ID 11 | No Event ID 11 recovered for C:\Users\yunpwint\Downloads\Test.pdf.exe | Original file-creation event was not captured |
