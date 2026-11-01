"""Behaviour rules: raw events -> explainable detections mapped to MITRE ATT&CK.

Every rule is a small pure function. A Detection carries the evidence (the
exact events that triggered it) so each claim in the final report can be
verified by a reviewer against the raw timeline.
"""
from __future__ import annotations

import math
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List
from urllib.parse import urlsplit

from .iocs import is_benign_domain, is_public_ip
from .schema import basename

Event = Dict[str, Any]

TECHNIQUES = {
    "T1204.002": "User Execution: Malicious File",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1027": "Obfuscated Files or Information",
    "T1105": "Ingress Tool Transfer",
    "T1218": "System Binary Proxy Execution",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1490": "Inhibit System Recovery",
    "T1486": "Data Encrypted for Impact",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1055": "Process Injection",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1568.002": "Dynamic Resolution: Domain Generation Algorithms",
    "T1571": "Non-Standard Port",
    "T1041": "Exfiltration Over C2 Channel",
    "T1070.004": "Indicator Removal: File Deletion",
    "T1082": "System Information Discovery",
    "T1016": "System Network Configuration Discovery",
    "T1033": "System Owner/User Discovery",
    "T1497.003": "Virtualization/Sandbox Evasion: Time Based Evasion",
    "T1555.003": "Credentials from Password Stores: Credentials from Web Browsers",
}

TACTIC_ORDER = ["Execution", "Persistence", "Defense Evasion", "Credential Access",
                "Discovery", "Command and Control", "Exfiltration", "Impact"]

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
          "rundll32.exe", "regsvr32.exe"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"}
COMMON_PORTS = {80, 443, 53, 123, 8080}


@dataclass
class Detection:
    id: str
    tactic: str
    technique: str
    technique_name: str
    title: str
    weight: int
    evidence: str
    events: List[int] = field(default_factory=list)
    t: float = 0.0


def _d(rule_id: str, tactic: str, tech: str, title: str, weight: int, evidence: str, evs: List[Event]) -> Detection:
    return Detection(rule_id, tactic, tech, TECHNIQUES.get(tech, ""), title, weight, evidence,
                     [e["idx"] for e in evs], min((e["t"] for e in evs), default=0.0))


def _of(events: Iterable[Event], *types: str) -> List[Event]:
    return [e for e in events if e["type"] in types]


def _cmd(e: Event) -> str:
    return (e.get("cmdline") or "").lower()


def _short(s: str, n: int = 140) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def shannon(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


# ------------------------------------------------------------------ rules
def r_office_shell(events, ctx):
    for e in _of(events, "process_create"):
        if basename(e.get("parent_image", "")) in OFFICE and basename(e.get("image", "")) in SHELLS:
            return [_d("OFFICE_SPAWNS_SHELL", "Execution", "T1204.002",
                       "Office application spawned a command interpreter (macro / exploit pattern)", 25,
                       f"{basename(e['parent_image'])} -> {basename(e['image'])}: {_short(e.get('cmdline', ''))}", [e])]
    return []


def r_powershell(events, ctx):
    out = []
    ps = [e for e in _of(events, "process_create")
          if basename(e.get("image", "")) in ("powershell.exe", "pwsh.exe")]
    flags = [e for e in ps if re.search(r"\s-(nop|noprofile|w(indowstyle)?\s+hidden|ep\s+bypass|executionpolicy\s+bypass)\b", _cmd(e))]
    if flags:
        out.append(_d("PS_EVASIVE_FLAGS", "Execution", "T1059.001",
                      "PowerShell launched with stealth flags (no profile / hidden window / policy bypass)", 15,
                      _short(flags[0].get("cmdline", "")), flags))
    enc = [e for e in ps if re.search(r"\s-(e|ec|enc|encodedcommand)\s+[a-z0-9+/=]{16,}", _cmd(e))]
    if enc:
        out.append(_d("PS_ENCODED", "Defense Evasion", "T1027", "Base64-encoded PowerShell command", 10,
                      _short(enc[0].get("cmdline", "")), enc))
    cradle = [e for e in _of(events, "process_create")
              if re.search(r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|"
                           r"bitsadmin.{0,40}/transfer|certutil.{0,40}-urlcache", _cmd(e))]
    if cradle:
        out.append(_d("DOWNLOAD_CRADLE", "Execution", "T1105", "Command line downloads a payload from the network", 20,
                      _short(cradle[0].get("cmdline", "")), cradle))
    return out


def r_lolbin(events, ctx):
    hits = [e for e in _of(events, "process_create")
            if re.search(r"mshta(\.exe)?\s+(https?:|vbscript:|javascript:)|regsvr32.{0,60}(scrobj|/i:http)|"
                         r"rundll32.{0,60}(javascript:|mshtml)", _cmd(e))]
    if hits:
        return [_d("LOLBIN_PROXY_EXEC", "Defense Evasion", "T1218",
                   "Signed system binary abused to proxy code execution", 15, _short(hits[0].get("cmdline", "")), hits)]
    return []


def r_persistence(events, ctx):
    out = []
    run = [e for e in _of(events, "registry_set")
           if re.search(r"\\currentversion\\(run|runonce)(\\|$)", e.get("key", ""), re.I)]
    startup = [e for e in _of(events, "file_write") if "\\start menu\\programs\\startup\\" in e.get("path", "").lower()]
    if run or startup:
        first = (run + startup)[0]
        what = (f"{first.get('key')} [{first.get('value_name', '')}] = {first.get('data', '')}"
                if run else first.get("path", ""))
        out.append(_d("PERSIST_RUN_KEY", "Persistence", "T1547.001", "Autostart persistence (Run key / Startup folder)", 25,
                      _short(what), run + startup))
    tasks = [e for e in _of(events, "scheduled_task")] + \
            [e for e in _of(events, "process_create") if re.search(r"schtasks(\.exe)?\s+/create", _cmd(e))]
    if tasks:
        e = tasks[0]
        out.append(_d("PERSIST_SCHTASK", "Persistence", "T1053.005", "Scheduled task created for persistence", 20,
                      _short(e.get("cmdline") or f"{e.get('name')} -> {e.get('command', '')}"), tasks))
    svcs = [e for e in _of(events, "service_create")] + \
           [e for e in _of(events, "process_create") if re.search(r"\bsc(\.exe)?\s+create\b", _cmd(e))]
    if svcs:
        e = svcs[0]
        out.append(_d("PERSIST_SERVICE", "Persistence", "T1543.003", "Windows service created", 20,
                      _short(e.get("cmdline") or f"{e.get('name')} -> {e.get('image_path', '')}"), svcs))
    return out


def r_defender(events, ctx):
    hits = [e for e in _of(events, "process_create")
            if re.search(r"set-mppreference.{0,40}disable|add-mppreference.{0,30}exclusion|sc\s+(stop|config)\s+windefend|"
                         r"disableantispyware|netsh\s+advfirewall\s+set.{0,40}state\s+off", _cmd(e))]
    hits += [e for e in _of(events, "registry_set") if re.search(r"disableantispyware|disablerealtimemonitoring",
                                                                 e.get("key", ""), re.I)]
    if hits:
        e = hits[0]
        return [_d("DEFENDER_TAMPER", "Defense Evasion", "T1562.001", "Security tooling disabled or excluded", 25,
                   _short(e.get("cmdline") or e.get("key", "")), hits)]
    return []


def r_inhibit_recovery(events, ctx):
    hits = [e for e in _of(events, "process_create")
            if re.search(r"vssadmin.{0,20}delete\s+shadows|wmic.{0,30}shadowcopy.{0,10}delete|wbadmin.{0,20}delete|"
                         r"bcdedit.{0,60}(recoveryenabled\s+no|ignoreallfailures)", _cmd(e))]
    if hits:
        return [_d("INHIBIT_RECOVERY", "Impact", "T1490", "Backups / shadow copies destroyed (ransomware precursor)", 35,
                   _short(hits[0].get("cmdline", "")), hits)]
    return []


def r_ransomware(events, ctx):
    renames = [e for e in _of(events, "file_rename") if e.get("new_path")]
    by_ext = defaultdict(list)
    for e in renames:
        by_ext[basename(e["new_path"]).rsplit(".", 1)[-1] if "." in basename(e["new_path"]) else ""].append(e)
    for ext, evs in by_ext.items():
        if ext and len(evs) >= 20:
            return [_d("MASS_ENCRYPTION", "Impact", "T1486", "Mass file renaming to a single new extension", 40,
                       f"{len(evs)} files renamed to .{ext}", evs)]
    return []


def r_lsass(events, ctx):
    hits = [e for e in _of(events, "process_access") if basename(e.get("target_image", "")) == "lsass.exe"]
    hits += [e for e in _of(events, "process_create") if "comsvcs" in _cmd(e) and "minidump" in _cmd(e)]
    if hits:
        e = hits[0]
        return [_d("LSASS_ACCESS", "Credential Access", "T1003.001", "LSASS memory accessed (credential dumping)", 35,
                   _short(e.get("cmdline") or f"{basename(e.get('image', ''))} -> lsass.exe access {e.get('access', '')}"), hits)]
    return []


def r_injection(events, ctx):
    hits = _of(events, "process_inject")
    if hits:
        e = hits[0]
        return [_d("PROCESS_INJECTION", "Defense Evasion", "T1055", "Code injected into another process", 25,
                   f"pid {e.get('pid')} -> {basename(e.get('target_image', '')) or e.get('target_pid')}", hits)]
    return []


def _host_of(e: Event) -> str:
    if e["type"] == "http_request":
        return (e.get("host") or (urlsplit(e.get("url", "")).hostname or "")).lower()
    return f"{e.get('dst_ip', '')}:{e.get('dst_port', '')}"


def r_beacon(events, ctx):
    groups = defaultdict(list)
    for e in _of(events, "http_request", "net_connect"):
        h = _host_of(e)
        if h and not is_benign_domain(h.split(":")[0]):
            groups[h].append(e)
    for host, evs in groups.items():
        if len(evs) < 4:
            continue
        ts = sorted(e["t"] for e in evs)
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 1]
        if len(gaps) >= 3 and statistics.mean(gaps) > 0:
            cv = statistics.pstdev(gaps) / statistics.mean(gaps)
            if cv <= 0.35:
                return [_d("C2_BEACONING", "Command and Control", "T1071.001", "Regular, periodic callbacks to one host", 25,
                           f"{host}: {len(evs)} requests, every ~{statistics.mean(gaps):.0f}s (jitter {cv:.0%})", evs)]
    return []


def r_dns_dga(events, ctx):
    hits = []
    for e in _of(events, "dns_query"):
        name = (e.get("name") or "").lower().rstrip(".")
        labels = name.split(".")
        if len(labels) < 2 or is_benign_domain(name):
            continue
        sld = labels[-2] if len(labels) >= 2 else labels[0]
        core = max(sld.split("-"), key=len)
        digits = sum(c.isdigit() for c in core)
        if len(core) >= 10 and digits >= 2 and shannon(core) >= 3.2:
            hits.append(e)
    if hits:
        return [_d("DGA_LIKE_DOMAIN", "Command and Control", "T1568.002", "High-entropy domain name (DGA-like)", 15,
                   ", ".join(sorted({h['name'] for h in hits})[:3]), hits)]
    return []


def r_odd_port(events, ctx):
    hits = [e for e in _of(events, "net_connect")
            if is_public_ip(e.get("dst_ip", "")) and int(e.get("dst_port") or 0) not in COMMON_PORTS]
    if hits:
        e = hits[0]
        return [_d("NON_STANDARD_PORT", "Command and Control", "T1571", "Outbound connection on an unusual port", 10,
                   f"{e.get('dst_ip')}:{e.get('dst_port')}", hits)]
    return []


def r_exfil(events, ctx):
    hits = [e for e in _of(events, "http_request")
            if e.get("method", "").upper() == "POST" and int(e.get("bytes_out") or 0) >= 100_000]
    if hits:
        e = hits[0]
        return [_d("LARGE_UPLOAD", "Exfiltration", "T1041", "Large HTTP POST to the contacted host", 20,
                   f"{e.get('url')} ({int(e['bytes_out']):,} bytes)", hits)]
    return []


def r_self_delete(events, ctx):
    name = basename(ctx["sample"].get("name", ""))
    hits = [e for e in _of(events, "file_delete") if name and basename(e.get("path", "")) == name]
    if hits:
        return [_d("SELF_DELETE", "Defense Evasion", "T1070.004", "Initial sample deleted after execution", 10,
                   hits[0].get("path", ""), hits)]
    return []


def r_discovery(events, ctx):
    pat = {"T1033": r"\bwhoami\b", "T1082": r"\bsysteminfo\b|\bhostname\b|ver\s*$",
           "T1016": r"ipconfig\s+/all|\barp\s+-a\b|\bnltest\b|\broute\s+print\b"}
    seen, evs = set(), []
    for e in _of(events, "process_create"):
        for tech, rx in pat.items():
            if re.search(rx, _cmd(e)):
                seen.add(tech)
                evs.append(e)
    if len(seen) >= 2:
        return [_d("HOST_DISCOVERY", "Discovery", sorted(seen)[0],
                   f"Host & network reconnaissance commands ({', '.join(sorted(seen))})", 10,
                   ", ".join(sorted({_short(e.get('cmdline', ''), 40) for e in evs})[:4]), evs)]
    return []


def r_sleep_evasion(events, ctx):
    hits = []
    for e in _of(events, "process_create"):
        c = _cmd(e)
        m = re.search(r"ping\s+(-n\s+(\d+)\s+127\.0\.0\.1|127\.0\.0\.1\s+-n\s+(\d+))", c)
        t = re.search(r"timeout(\.exe)?\s+/t\s+(\d+)", c)
        if (m and int(m.group(2) or m.group(3)) >= 10) or (t and int(t.group(2)) >= 30):
            hits.append(e)
    if hits:
        return [_d("TIME_BASED_EVASION", "Defense Evasion", "T1497.003", "Artificial delay (ping/timeout) to outwait sandboxes", 10,
                   _short(hits[0].get("cmdline", "")), hits)]
    return []


def r_browser_creds(events, ctx):
    hits = [e for e in _of(events, "file_read")
            if re.search(r"login data|logins\.json|key4\.db|\\cookies$|web data", e.get("path", ""), re.I)
            and basename(e.get("image", "") or ctx.get("image_by_pid", {}).get(e.get("pid"), "")) not in BROWSERS]
    if hits:
        return [_d("BROWSER_CRED_THEFT", "Credential Access", "T1555.003", "Browser credential store read by a non-browser process", 30,
                   hits[0].get("path", ""), hits)]
    return []


RULES: List[Callable] = [
    r_office_shell, r_powershell, r_lolbin, r_persistence, r_defender, r_inhibit_recovery, r_ransomware,
    r_lsass, r_injection, r_beacon, r_dns_dga, r_odd_port, r_exfil, r_self_delete, r_discovery,
    r_sleep_evasion, r_browser_creds,
]


def run_rules(report: Dict[str, Any]) -> List[Detection]:
    events = report["events"]
    image_by_pid = {e.get("pid"): e.get("image", "") for e in events if e["type"] == "process_create"}
    ctx = {"sample": report["sample"], "image_by_pid": image_by_pid}
    found: List[Detection] = []
    for rule in RULES:
        found.extend(rule(events, ctx))
    return sorted(found, key=lambda d: (d.t, -d.weight))
