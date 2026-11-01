# Malware Sandbox Report — setup_notepad_tool.exe

> **Generated:** 2026-11-01 08:28 UTC · **Tool:** sandboxscribe 1.0.0 · **SHA-256:** `7c3f9a1e5b2d4c8a6e0f1b3d5a7c9e2f4b6d8a0c1e3f5a7b9d1c3e5f7a9b1c3d`

## 1. Verdict

### 🟢 NO MALICIOUS BEHAVIOUR OBSERVED — score 0/100 — confidence MEDIUM

No rule fired in this detonation. A sandbox can only report what it **saw**: environment checks, long sleeps or missing user interaction can hide behaviour. Treat as *not proven benign*.

## 3. Containment recommendation

**Immediate (stop the spread)**

- No containment required on this evidence. Keep the report with the ticket.

**Hunt (find the siblings)**

- Re-detonate with a longer runtime and user-interaction simulation before declaring the file safe: absence of behaviour in a sandbox is not proof of benignity.

---

## 4. Sample & environment

| Field | Value |
|---|---|
| Name | setup_notepad_tool.exe |
| Type | PE32 installer (SYNTHETIC training sample) |
| Size | 2,411,008 bytes |
| SHA-256 | 7c3f9a1e5b2d4c8a6e0f1b3d5a7c9e2f4b6d8a0c1e3f5a7b9d1c3e5f7a9b1c3d |
| SHA-1 |  |
| MD5 |  |
| Sandbox | isolated VM + Sysmon (synthetic) |
| OS | Windows 10 22H2 x64 |
| Runtime | 120 s |
| Network mode | simulated |
| Events analysed | 7 |

## 5. Process tree

```text
setup_notepad_tool.exe (pid 900)  "C:\Users\analyst\Downloads\setup_notepad_tool.exe" /S
└─ notepadtool.exe (pid 910)  "C:\Program Files\NotepadTool\notepadtool.exe"
```

## 6. Behaviour timeline

| T+ (s) | Event | Detections |
|---|---|---|
| 0.0 | Process started: setup_notepad_tool.exe — "C:\Users\analyst\Downloads\setup_notepad_tool.exe" /S |  |
| 3.2 | File written: C:\Program Files\NotepadTool\notepadtool.exe |  |
| 3.4 | File written: C:\Program Files\NotepadTool\readme.txt |  |
| 4.0 | Registry set: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NotepadTool [DisplayName] = Notepad Tool |  |
| 5.1 | DNS query: www.msftconnecttest.com → 198.51.100.201 |  |
| 5.9 | DNS query: ocsp.digicert.com → 198.51.100.202 |  |
| 7.0 | Process started: notepadtool.exe — "C:\Program Files\NotepadTool\notepadtool.exe" |  |

## 7. Detections & MITRE ATT&CK

_none_

## 8. Indicators of compromise (defanged)

| Type | Value | Context |
|---|---|---|
| sha256 | 7c3f9a1e5b2d4c8a6e0f1b3d5a7c9e2f4b6d8a0c1e3f5a7b9d1c3e5f7a9b1c3d | sample setup_notepad_tool.exe |

_2 OS / vendor noise indicators were filtered out (Microsoft update, certificate checks, …)._
