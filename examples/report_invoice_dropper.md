# Malware Sandbox Report — Invoice_2025-10.docm

> **Generated:** 2026-11-01 08:29 UTC · **Tool:** sandboxscribe 1.0.0 · **SHA-256:** `2ff95d39ccb5653f0a920649c46bb2c28e0cb67d3b1fb9b9989a5bd430891483`

## 1. Verdict

### 🔴 MALICIOUS — score 100/100 — confidence HIGH

## 2. What the sample does

1. **Execution** — Office application spawned a command interpreter (macro / exploit pattern). _winword.exe -> cmd.exe: cmd.exe /c powershell -nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAcwB5AG4AdABoAGUAdABpAGMAIABzAGEAbQBwAGwAZQAgAC0AIABpAG4AZQByAHQAJ…_
2. **Persistence** — Autostart persistence (Run key / Startup folder). _HKCU\Software\Microsoft\Windows\CurrentVersion\Run [WindowsUpdateHelper] = C:\Users\analyst\AppData\Roaming\Microsoft\Windows\svchost32.exe_
3. **Defense Evasion** — Security tooling disabled or excluded. _powershell -c Add-MpPreference -ExclusionPath C:\Users\analyst\AppData\Roaming_
4. **Defense Evasion** — Code injected into another process. _pid 5600 -> explorer.exe_
5. **Persistence** — Scheduled task created for persistence. _schtasks /create /tn "WinUpdHelper" /tr "C:\Users\analyst\AppData\Roaming\Microsoft\Windows\svchost32.exe" /sc onlogon_
6. **Credential Access** — Browser credential store read by a non-browser process. _C:\Users\analyst\AppData\Local\Google\Chrome\User Data\Default\Login Data_
7. **Command and Control** — Regular, periodic callbacks to one host. _203.0.113.45: 6 requests, every ~27s (jitter 23%)_

## 3. Containment recommendation

**Immediate (stop the spread)**

- Isolate every host that executed the sample (EDR network containment) and kill the process tree shown in the report.
- Block at DNS / proxy / firewall: update-cdn-7x2k9qv4mz.example, 203.0.113.45.
- Block the sample hash 2ff95d39ccb5653f… in EDR / mail gateway and purge the delivering message from all mailboxes.
- Disable macros from the internet (Mark-of-the-Web policy) until the delivery path is closed.

**Eradicate (remove what it installed)**

- Delete registry persistence HKCU\Software\Microsoft\Windows\CurrentVersion\Run value 'WindowsUpdateHelper' (points to C:\Users\analyst\AppData\Roaming\Microsoft\Windows\svchost32.exe).
- Delete the scheduled task(s) created by the sample (schtasks /delete) and review all tasks created in the window.
- Remove dropped file C:\Users\analyst\AppData\Roaming\Microsoft\Windows\svchost32.exe (sha256 9a496227eda4…).
- Remove added Defender exclusions / re-enable real-time protection and verify tamper protection.
- Memory-image the injected host before reboot: a clean-looking host process may still hold the payload. Reimage if in doubt.

**Hunt (find the siblings)**

- Search EDR / SIEM for the sample hashes and dropped-file names across the whole fleet over the last 30 days.
- Search proxy / DNS / NetFlow history for the domains and IPs; each hit is a potentially compromised host.
- Hunt for the mutex name(s) in EDR telemetry: they survive recompilation of the payload.
- Deploy the generated Sigma rules (see sigma/) as detections, then back-test them on 30 days of logs.
- Look for periodic outbound traffic with the same interval/jitter from other hosts (beaconing analytics).

**Recover & communicate**

- Assume credentials on the host are stolen: reset passwords, revoke sessions/tokens and rotate any secrets stored in the browser or on the machine.
- Possible data exfiltration: determine what the process could read, and involve legal / DPO if personal data is in scope.
- Notify affected users, submit the sample to the AV vendor and share IOCs with trusted partners (ISAC / CERT).
- Record the case and update the detection backlog with every TTP that was not alerted on.

---

## 4. Sample & environment

| Field | Value |
|---|---|
| Name | Invoice_2025-10.docm |
| Type | Word document with macros (SYNTHETIC training sample) |
| Size | 48,213 bytes |
| SHA-256 | 2ff95d39ccb5653f0a920649c46bb2c28e0cb67d3b1fb9b9989a5bd430891483 |
| SHA-1 | 1766dfcb4b5c89e6401b72c15bed6f5d37fb887f |
| MD5 | a2bbbcda67afc8a0c579a2747ad6fdc7 |
| Sandbox | isolated VM + Sysmon (synthetic) |
| OS | Windows 10 22H2 x64 |
| Runtime | 180 s |
| Network mode | simulated internet (INetSim-style), no real egress |
| Events analysed | 26 |

## 5. Process tree

```text
winword.exe (pid 4120)  "WINWORD.EXE" "C:\Users\analyst\Desktop\Invoice_2025-10.docm"
└─ cmd.exe (pid 5208)  cmd.exe /c powershell -nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAcwB5AG
   └─ powershell.exe (pid 5320)  powershell -nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAcwB5AG4AdABoAGUAd
      └─ svchost32.exe (pid 5600)  C:\Users\analyst\AppData\Roaming\Microsoft\Windows\svchost32.exe
         ├─ powershell.exe (pid 5730)  powershell -c Add-MpPreference -ExclusionPath C:\Users\analyst\AppData\Roaming
         ├─ schtasks.exe (pid 5710)  schtasks /create /tn "WinUpdHelper" /tr "C:\Users\analyst\AppData\Roaming\Micros
         ├─ whoami.exe (pid 5741)  whoami /all
         ├─ systeminfo.exe (pid 5742)  systeminfo
         ├─ ipconfig.exe (pid 5743)  ipconfig /all
         └─ cmd.exe (pid 5800)  cmd.exe /c ping -n 30 127.0.0.1 > nul & del "C:\Users\analyst\Desktop\Invoice_20
```

## 6. Behaviour timeline

| T+ (s) | Event | Detections |
|---|---|---|
| 0.0 | Process started: winword.exe — "WINWORD.EXE" "C:\Users\analyst\Desktop\Invoice_2025-10.docm" |  |
| 2.1 | DNS query: settings-win.data.microsoft.com → 198.51.100.200 |  |
| 8.4 | Process started: cmd.exe — cmd.exe /c powershell -nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAcwB5AG4AdABoAGUAdABpAGMAIABzAGEAbQBw | OFFICE_SPAWNS_SHELL |
| 8.9 | Process started: powershell.exe — powershell -nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAcwB5AG4AdABoAGUAdABpAGMAIABzAGEAbQBwAGwAZQAgAC0 | PS_EVASIVE_FLAGS, PS_ENCODED |
| 10.2 | DNS query: update-cdn-7x2k9qv4mz.example → 203.0.113.45 | DGA_LIKE_DOMAIN |
| 10.5 | HTTP GET http://update-cdn-7x2k9qv4mz.example/stage2.bin |  |
| 11.0 | File written: C:\Users\analyst\AppData\Roaming\Microsoft\Windows\svchost32.exe |  |
| 11.4 | Mutex created: Global\SynthMutex-7Q2K |  |
| 12.0 | Process started: svchost32.exe — C:\Users\analyst\AppData\Roaming\Microsoft\Windows\svchost32.exe |  |
| 12.6 | Registry set: HKCU\Software\Microsoft\Windows\CurrentVersion\Run [WindowsUpdateHelper] = C:\Users\analyst\AppData\Roaming\Microsoft\Windows\svchost32.exe | PERSIST_RUN_KEY |
| 13.0 | Process started: powershell.exe — powershell -c Add-MpPreference -ExclusionPath C:\Users\analyst\AppData\Roaming | DEFENDER_TAMPER |
| 13.4 | Injection: pid 5600 → explorer.exe | PROCESS_INJECTION |
| 13.8 | Process started: schtasks.exe — schtasks /create /tn "WinUpdHelper" /tr "C:\Users\analyst\AppData\Roaming\Microsoft\Windows\svchost32.exe" /sc | PERSIST_SCHTASK |
| 14.2 | Process started: whoami.exe — whoami /all | HOST_DISCOVERY |
| 14.4 | Process started: systeminfo.exe — systeminfo | HOST_DISCOVERY |
| 14.7 | Process started: ipconfig.exe — ipconfig /all | HOST_DISCOVERY |
| 15.3 | File read: C:\Users\analyst\AppData\Local\Google\Chrome\User Data\Default\Login Data | BROWSER_CRED_THEFT |
| 20.0 | Connection: 203.0.113.45:8443/tcp | NON_STANDARD_PORT |
| 30.2 | HTTP POST http://203.0.113.45:8443/gate (412 B out) | C2_BEACONING |
| 60.1 | HTTP POST http://203.0.113.45:8443/gate (413 B out) | C2_BEACONING |
| 90.4 | HTTP POST http://203.0.113.45:8443/gate (414 B out) | C2_BEACONING |
| 120.2 | HTTP POST http://203.0.113.45:8443/gate (415 B out) | C2_BEACONING |
| 150.3 | HTTP POST http://203.0.113.45:8443/gate (416 B out) | C2_BEACONING |
| 165.0 | HTTP POST http://203.0.113.45:8443/upload (524,288 B out) | C2_BEACONING, LARGE_UPLOAD |
| 170.0 | Process started: cmd.exe — cmd.exe /c ping -n 30 127.0.0.1 > nul & del "C:\Users\analyst\Desktop\Invoice_2025-10.docm" | TIME_BASED_EVASION |
| 172.0 | File deleted: C:\Users\analyst\Desktop\Invoice_2025-10.docm | SELF_DELETE |

## 7. Detections & MITRE ATT&CK

| Weight | Tactic | Technique | Finding | Evidence |
|---|---|---|---|---|
| 30 | Credential Access | T1555.003 Credentials from Password Stores: Credentials from Web Browsers | Browser credential store read by a non-browser process | C:\Users\analyst\AppData\Local\Google\Chrome\User Data\Default\Login Data |
| 25 | Execution | T1204.002 User Execution: Malicious File | Office application spawned a command interpreter (macro / exploit pattern) | winword.exe -> cmd.exe: cmd.exe /c powershell -nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAcwB5AG4AdABoAGUAdABpAGMAIABzAGEAbQBwAGwAZQAgAC0AIABpAG4AZQByAHQAJ… |
| 25 | Persistence | T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Autostart persistence (Run key / Startup folder) | HKCU\Software\Microsoft\Windows\CurrentVersion\Run [WindowsUpdateHelper] = C:\Users\analyst\AppData\Roaming\Microsoft\Windows\svchost32.exe |
| 25 | Defense Evasion | T1562.001 Impair Defenses: Disable or Modify Tools | Security tooling disabled or excluded | powershell -c Add-MpPreference -ExclusionPath C:\Users\analyst\AppData\Roaming |
| 25 | Defense Evasion | T1055 Process Injection | Code injected into another process | pid 5600 -> explorer.exe |
| 25 | Command and Control | T1071.001 Application Layer Protocol: Web Protocols | Regular, periodic callbacks to one host | 203.0.113.45: 6 requests, every ~27s (jitter 23%) |
| 20 | Persistence | T1053.005 Scheduled Task/Job: Scheduled Task | Scheduled task created for persistence | schtasks /create /tn "WinUpdHelper" /tr "C:\Users\analyst\AppData\Roaming\Microsoft\Windows\svchost32.exe" /sc onlogon |
| 20 | Exfiltration | T1041 Exfiltration Over C2 Channel | Large HTTP POST to the contacted host | http://203.0.113.45:8443/upload (524,288 bytes) |
| 15 | Execution | T1059.001 Command and Scripting Interpreter: PowerShell | PowerShell launched with stealth flags (no profile / hidden window / policy bypass) | powershell -nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAcwB5AG4AdABoAGUAdABpAGMAIABzAGEAbQBwAGwAZQAgAC0AIABpAG4AZQByAHQAJwA= |
| 15 | Command and Control | T1568.002 Dynamic Resolution: Domain Generation Algorithms | High-entropy domain name (DGA-like) | update-cdn-7x2k9qv4mz.example |
| 10 | Defense Evasion | T1027 Obfuscated Files or Information | Base64-encoded PowerShell command | powershell -nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAcwB5AG4AdABoAGUAdABpAGMAIABzAGEAbQBwAGwAZQAgAC0AIABpAG4AZQByAHQAJwA= |
| 10 | Discovery | T1016 System Network Configuration Discovery | Host & network reconnaissance commands (T1016, T1033, T1082) | ipconfig /all, systeminfo, whoami /all |
| 10 | Command and Control | T1571 Non-Standard Port | Outbound connection on an unusual port | 203.0.113.45:8443 |
| 10 | Defense Evasion | T1497.003 Virtualization/Sandbox Evasion: Time Based Evasion | Artificial delay (ping/timeout) to outwait sandboxes | cmd.exe /c ping -n 30 127.0.0.1 > nul & del "C:\Users\analyst\Desktop\Invoice_2025-10.docm" |
| 10 | Defense Evasion | T1070.004 Indicator Removal: File Deletion | Initial sample deleted after execution | C:\Users\analyst\Desktop\Invoice_2025-10.docm |

**Kill-chain coverage:** **Execution** → **Persistence** → **Defense Evasion** → **Credential Access** → **Discovery** → **Command and Control** → **Exfiltration** → ~~Impact~~

## 8. Indicators of compromise (defanged)

| Type | Value | Context |
|---|---|---|
| sha256 | 2ff95d39ccb5653f0a920649c46bb2c28e0cb67d3b1fb9b9989a5bd430891483 | sample Invoice_2025-10.docm |
| md5 | a2bbbcda67afc8a0c579a2747ad6fdc7 | sample Invoice_2025-10.docm |
| sha1 | 1766dfcb4b5c89e6401b72c15bed6f5d37fb887f | sample Invoice_2025-10.docm |
| sha256 | 9a496227eda43e61e28c028ac3db3b66322fcb051282861b2e5dd3c109a6a560 | dropped svchost32.exe |
| domain | update-cdn-7x2k9qv4mz[.]example | contacted |
| ip | 203[.]0[.]113[.]45 | contacted |
| url | hxxp://203[.]0[.]113[.]45:8443/gate | requested |
| url | hxxp://203[.]0[.]113[.]45:8443/upload | requested |
| url | hxxp://update-cdn-7x2k9qv4mz[.]example/stage2[.]bin | requested |
| mutex | Global\SynthMutex-7Q2K | created |
| registry | HKCU\Software\Microsoft\Windows\CurrentVersion\Run | data=C:\Users\analyst\AppData\Roaming\Microsoft\Windows\svchost32.exe |
| file | C:\Users\analyst\AppData\Roaming\Microsoft\Windows\svchost32.exe | dropped |

_1 OS / vendor noise indicators were filtered out (Microsoft update, certificate checks, …)._

## 9. Detection rules generated (Sigma)

Written to `--sigma-dir`: `dns_c2_2ff95d39ccb5.yml`, `dropped_file_2ff95d39ccb5.yml`, `net_c2_2ff95d39ccb5.yml`, `office_spawns_shell_2ff95d39ccb5.yml`, `persist_run_key_2ff95d39ccb5.yml`

Example — `dns_c2_2ff95d39ccb5.yml`:

```yaml
title: DNS Query to Domain Contacted by Analysed Sample
id: 6c98c1f4-5b21-5f72-87ab-85fdf331aede
status: experimental
description: Domains resolved by the sample during detonation.
author: SandboxScribe
date: 2026/11/01
tags:
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
            - 'update-cdn-7x2k9qv4mz.example'
    condition: selection
falsepositives:
    - Legitimate use of the same binaries/paths; tune before production
level: high
```
