# Lab 04: Host Forensics & Suspicious Process Execution Triage (Sysmon & PowerShell)

## 1. Executive Summary & Objective
Following network triage (`Lab 03`), host-level forensic analysis was conducted on host `Vince-Desktop` to investigate a secondary persistence and payload execution attempt. Utilizing Windows Event Logs (Sysmon Event ID 1: Process Creation) ingested into Splunk, an obfuscated Base64 PowerShell execution was detected, decoded, and analyzed for local system impacts.

---

## 2. Attack Chain & Triage Timeline

| Event ID | Source | Process / Image | Target / Executed Command | Threat Indicator |
| :---: | :--- | :--- | :--- | :--- |
| **Sysmon 1** | `cmd.exe` | `powershell.exe` | `-e aGVscA==` / Encoded Payload | Suspicious Parent-Child Process |
| **Sysmon 3** | `powershell.exe` | Network Connection | Outbound to C2 IP `203.0.113.42` | Payload Callback |
| **Win 4688** | `services.exe` | `reg.exe` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Registry Persistence |

---

## 3. Splunk Investigation & Payload Deobfuscation Query

To identify encoded PowerShell execution across endpoints:

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe*"
| stats count by host, User, ParentImage, CommandLine
| where match(CommandLine, "(?i)-e(nc(odedcommand)?)?")
