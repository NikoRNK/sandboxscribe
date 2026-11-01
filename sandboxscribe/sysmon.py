"""Adapter: Sysmon events exported as JSON (array or one object per line).

This is the realistic path for the "isolated VM" workflow: detonate in a
snapshot-restored Windows VM with Sysmon installed, export the Microsoft-
Windows-Sysmon/Operational events as JSON, and let SandboxScribe do the rest.

Handled Sysmon event IDs:
  1 process create · 3 network connect · 8 CreateRemoteThread · 10 ProcessAccess
  11 file create · 13 registry value set · 22 DNS query · 23 file delete
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _flat(row: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    def walk(d: Dict[str, Any]) -> None:
        for k, v in d.items():
            if isinstance(v, dict):
                walk(v)
            else:
                out[k] = v

    walk(row)
    return out


def _parse_time(value: Any) -> Optional[datetime]:
    s = str(value or "").strip()
    if not s:
        return None
    s = re.sub(r"(\.\d{6})\d+", r"\1", s.replace("Z", "+00:00"))
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def read_rows(path: str) -> List[Dict[str, Any]]:
    text = Path(path).read_text(encoding="utf-8-sig").strip()
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def _sha256(hashes: Any) -> str:
    m = re.search(r"SHA256=([0-9A-Fa-f]{64})", str(hashes or ""))
    return m.group(1).lower() if m else ""


def convert(rows: List[Dict[str, Any]], sample: Optional[Dict[str, Any]] = None,
            environment: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    flat = [_flat(r) for r in rows]
    times = [_parse_time(r.get("UtcTime") or r.get("SystemTime")) for r in flat]
    known = [t for t in times if t]
    t0 = min(known) if known else None
    events: List[Dict[str, Any]] = []
    for r, ts in zip(flat, times):
        try:
            eid = int(str(r.get("EventID", "")).strip())
        except ValueError:
            continue
        t = (ts - t0).total_seconds() if ts and t0 else 0.0
        pid = r.get("ProcessId") or r.get("SourceProcessId")
        base = {"t": t, "pid": pid}
        if eid == 1:
            events.append({**base, "type": "process_create", "ppid": r.get("ParentProcessId"),
                           "image": r.get("Image", ""), "cmdline": r.get("CommandLine", ""),
                           "parent_image": r.get("ParentImage", ""), "sha256": _sha256(r.get("Hashes"))})
        elif eid == 3:
            events.append({**base, "type": "net_connect", "dst_ip": r.get("DestinationIp", ""),
                           "dst_port": int(r.get("DestinationPort") or 0), "proto": r.get("Protocol", "tcp"),
                           "image": r.get("Image", "")})
        elif eid == 8:
            events.append({**base, "type": "process_inject", "image": r.get("SourceImage", ""),
                           "target_pid": r.get("TargetProcessId"), "target_image": r.get("TargetImage", "")})
        elif eid == 10:
            events.append({**base, "type": "process_access", "image": r.get("SourceImage", ""),
                           "target_image": r.get("TargetImage", ""), "access": r.get("GrantedAccess", "")})
        elif eid == 11:
            events.append({**base, "type": "file_write", "path": r.get("TargetFilename", ""), "image": r.get("Image", "")})
        elif eid == 13:
            events.append({**base, "type": "registry_set", "key": r.get("TargetObject", ""),
                           "data": r.get("Details", ""), "image": r.get("Image", "")})
        elif eid == 22:
            answers = IPV4.findall(str(r.get("QueryResults", "")))
            events.append({**base, "type": "dns_query", "name": r.get("QueryName", ""),
                           "answers": answers, "image": r.get("Image", "")})
        elif eid == 23:
            events.append({**base, "type": "file_delete", "path": r.get("TargetFilename", ""), "image": r.get("Image", "")})
    return {"sample": sample or {}, "environment": environment or
            {"sandbox": "manual VM + Sysmon", "os": "Windows (Sysmon export)",
             "duration_s": int(max((e["t"] for e in events), default=0)), "network": "unknown"},
            "events": events}
