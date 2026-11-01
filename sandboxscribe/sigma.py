"""Generate Sigma rules from what the sample did.

The goal is to turn one detonation into durable detections. Rules are
intentionally narrow (observed values only) so they are low-noise starters
that a detection engineer then generalises.
"""
from __future__ import annotations

import re
import uuid
from datetime import date
from typing import Any, Dict, List

from .rules import Detection
from .schema import basename


def _q(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _rule(title: str, desc: str, category: str, selection: Dict[str, List[str]], tags: List[str],
          level: str, key: str, author: str) -> str:
    rid = uuid.uuid5(uuid.NAMESPACE_URL, "sandboxscribe/" + key)
    lines = [f"title: {title}", f"id: {rid}", "status: experimental", f"description: {desc}",
             f"author: {author}", f"date: {date.today().strftime('%Y/%m/%d')}",
             "tags:"] + [f"    - {t}" for t in tags] + \
            ["logsource:", f"    category: {category}", "    product: windows", "detection:", "    selection:"]
    for field_name, values in selection.items():
        lines.append(f"        {field_name}:")
        lines += [f"            - {_q(v)}" for v in values]
    lines += ["    condition: selection", "falsepositives:", "    - Legitimate use of the same binaries/paths; tune before production",
              f"level: {level}"]
    return "\n".join(lines) + "\n"


def _tag(tech: str) -> str:
    return "attack." + tech.lower()


def generate(report: Dict[str, Any], detections: List[Detection], iocs: Dict[str, Any],
             author: str = "SandboxScribe") -> Dict[str, str]:
    """Return {filename: yaml}."""
    sha = (report["sample"].get("sha256") or "nosha")[:12]
    out: Dict[str, str] = {}
    ids = {d.id for d in detections}
    events = report["events"]

    if "OFFICE_SPAWNS_SHELL" in ids:
        pairs = {(basename(e["parent_image"]), basename(e["image"])) for e in events
                 if e["type"] == "process_create" and basename(e.get("parent_image", "")) in
                 {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe"}
                 and basename(e.get("image", "")) in {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                                                       "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}}
        parents = sorted({p for p, _ in pairs})
        kids = sorted({c for _, c in pairs})
        out[f"office_spawns_shell_{sha}.yml"] = _rule(
            "Office Application Spawns Command Interpreter (observed in sandbox)",
            "Child process of an Office application matching behaviour seen during detonation.",
            "process_creation",
            {"ParentImage|endswith": ["\\" + p for p in parents], "Image|endswith": ["\\" + c for c in kids]},
            ["attack.execution", "attack.t1204.002"], "high", "office" + sha, author)
        # Sigma ANDs different fields and ORs list values: exactly the semantics we want.

    if iocs["domains"]:
        out[f"dns_c2_{sha}.yml"] = _rule(
            "DNS Query to Domain Contacted by Analysed Sample",
            "Domains resolved by the sample during detonation.", "dns_query",
            {"QueryName|endswith": iocs["domains"]},
            ["attack.command-and-control", "attack.t1071.001"], "high", "dns" + sha, author)

    if iocs["ips"]:
        out[f"net_c2_{sha}.yml"] = _rule(
            "Network Connection to IP Contacted by Analysed Sample",
            "Public IPs contacted by the sample during detonation.", "network_connection",
            {"DestinationIp": iocs["ips"]},
            ["attack.command-and-control"], "high", "net" + sha, author)

    if iocs["registry"]:
        targets = []
        for r in iocs["registry"]:
            key = r["key"].split("\\", 1)[-1] if "\\" in r["key"] else r["key"]
            targets.append("\\" + key.split("\\")[-1] + ("\\" + r["value_name"] if r["value_name"] else ""))
        out[f"persist_run_key_{sha}.yml"] = _rule(
            "Registry Persistence Value Set by Analysed Sample",
            "Autostart registry value created during detonation.", "registry_set",
            {"TargetObject|endswith": sorted(set(targets))},
            ["attack.persistence", "attack.t1547.001"], "high", "reg" + sha, author)

    drops = [basename(f["path"]) for f in iocs["dropped_files"] if f["path"].lower().endswith((".exe", ".dll", ".scr"))]
    if drops:
        out[f"dropped_file_{sha}.yml"] = _rule(
            "Executable Dropped to User-Writable Path by Analysed Sample",
            "File names written by the sample during detonation.", "file_event",
            {"TargetFilename|endswith": sorted({"\\" + d for d in drops})},
            ["attack.execution", "attack.t1204.002"], "medium", "file" + sha, author)
    return out
