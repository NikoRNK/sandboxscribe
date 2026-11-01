# Methodology — "the report is the deliverable, the sandbox is just the tool"

Every SOC receives suspicious attachments. Detonating one is the easy part; the
value an analyst adds is turning raw behaviour into a decision someone can act
on. SandboxScribe encodes that translation.

| Stage | Question | Module | Output |
|-------|----------|--------|--------|
| 1 Detonate safely | What happened? | *(your sandbox / VM)* | Telemetry (events) |
| 2 Normalize | Can any sandbox feed the same analysis? | `schema.py`, `sysmon.py` | One event schema |
| 3 Detect | Which behaviours are malicious, and why? | `rules.py` | Detections + ATT&CK techniques + evidence |
| 4 Extract | What can I block and hunt? | `iocs.py` | Defanged, noise-filtered IOCs |
| 5 Explain | In what order did it happen? | `timeline.py` | Process tree + behaviour timeline |
| 6 Decide | What do I do about it? | `containment.py` | Tiered containment recommendation |
| 7 Operationalise | How do I catch it next time? | `sigma.py` | Sigma rules |

## Design principles

* **Explainable detections.** Each rule is a small pure function returning the
  *exact events* that triggered it. A reviewer can open the timeline and verify
  every claim.
* **Behaviour over signatures.** Hashes change on every recompilation; "Office
  spawns an encoded PowerShell, writes a Run key and beacons every 30 s" does not.
* **Noise filtering.** OS and vendor traffic (Windows Update, certificate
  revocation) is excluded from the IOC list so blocklists stay clean.
* **Recommendations derived from evidence.** Containment lines appear only when
  the corresponding behaviour was observed (no ransomware advice unless
  shadow copies were deleted or files mass-renamed).
* **Intel confirms, never invents.** VirusTotal / MalwareBazaar lookups are
  hash-only; ≥10 VirusTotal engines or a MalwareBazaar signature can escalate a
  verdict, but the behavioural evidence stays the primary basis.

## Verdict & confidence

| Score (sum of weights, cap 100) | Verdict |
|---|---|
| ≥ 60 (or intel-confirmed) | `MALICIOUS` |
| 25 – 59 | `SUSPICIOUS` |
| < 25 | `NO MALICIOUS BEHAVIOUR OBSERVED` |

Confidence reflects how many distinct ATT&CK tactics support the verdict.
For a clean result confidence is `LOW` when the run was shorter than 60 s.

**"No malicious behaviour observed" is deliberately not "benign".** A sandbox
only reports what it saw. Environment checks, long sleeps, missing user
interaction or an unreachable C2 can hide behaviour. The report says so.

## Known limitations

* Heuristic rules over normalized telemetry: sophisticated, VM-aware samples
  can evade the underlying sandbox before SandboxScribe ever sees them.
* Telemetry quality bounds report quality (no Sysmon file-create events → no
  dropped-file IOCs).
* `file_read` events (used by the browser-credential rule) are not produced by a
  default Sysmon config; they come from sandboxes with file-access tracing.
* Sigma rules are narrow starters built from observed values; a detection
  engineer must generalise and test them before production.
