# Detonating safely — lab rules

The sandbox is just the tool; **how** you use it is what a hiring manager
checks first. SandboxScribe never executes anything: it analyses telemetry that
was already collected. These are the practices to follow while collecting it.

## Where to detonate

1. **Hosted sandbox (easiest, safest):** ANY.RUN or a similar service. The
   sample runs in their infrastructure, not yours. Never upload anything
   confidential or customer-related to a public service.
2. **Your own isolated VM:** a throw-away Windows VM you can revert.

## Isolated VM checklist

- [ ] Dedicated VM restored from a **clean snapshot** before every run
- [ ] **No shared folders, no clipboard sharing, no drag & drop**, no USB passthrough
- [ ] Network: *host-only / no route to the internet or your LAN*; use a fake
      internet (INetSim / FakeNet-NG style) so the sample "calls home" harmlessly
- [ ] The VM holds **no real credentials, no accounts signed in, no personal files**
- [ ] Hypervisor and host fully patched; the host is not your work machine
- [ ] Sysmon installed with a community configuration, plus an event export step (below)
- [ ] Samples stay inside the VM in a password-protected archive until used
- [ ] You are **allowed** to handle the sample (employer policy, lab agreement)

## Choosing a sample

Use samples from a research repository such as **MalwareBazaar** (free,
purpose-built for analysts). Prefer commodity, well-documented families.
Never test on files you cannot account for.

> **Never commit malware to GitHub.** This repository ships only *telemetry*
> (`samples/*.json`, `*.ndjson`), which is inert text. The `.gitignore`
> blocks `.exe`, `.dll` and `.zip`.

## Exporting Sysmon events to JSON (inside the VM, after the run)

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -Oldest |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $o = [ordered]@{ EventID = $_.Id }
    foreach ($d in $x.Event.EventData.Data) { $o[$d.Name] = $d.'#text' }
    $o | ConvertTo-Json -Compress
  } | Out-File sysmon.ndjson -Encoding utf8
```

Validate the export on a harmless action first (open Notepad, then check the
file). Move only `sysmon.ndjson` out of the VM, then revert the snapshot.

```bash
sandboxscribe report sysmon.ndjson --sample-name dropper.js --sample-sha256 <sha256> \
    --out report.md --sigma-dir sigma/
```

## After the run

1. Revert the snapshot. Do not reuse a dirty VM.
2. Defang every IOC before pasting it anywhere (SandboxScribe does this).
3. Keep the raw telemetry with the case: the report must be reproducible.
