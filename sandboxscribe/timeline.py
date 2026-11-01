"""Process tree and behaviour timeline."""
from __future__ import annotations

from typing import Any, Dict, List

from .rules import Detection
from .schema import basename


def describe(e: Dict[str, Any]) -> str:
    """One human-readable line per event."""
    t = e["type"]
    if t == "process_create":
        return f"Process started: {basename(e.get('image', ''))} — {' '.join(str(e.get('cmdline', '')).split())[:110]}"
    if t == "process_inject":
        return f"Injection: pid {e.get('pid')} → {basename(e.get('target_image', '')) or e.get('target_pid')}"
    if t == "process_access":
        return f"Process access: {basename(e.get('image', ''))} → {basename(e.get('target_image', ''))} ({e.get('access', '')})"
    if t == "file_write":
        return f"File written: {e.get('path', '')}"
    if t == "file_read":
        return f"File read: {e.get('path', '')}"
    if t == "file_delete":
        return f"File deleted: {e.get('path', '')}"
    if t == "file_rename":
        return f"File renamed: {basename(e.get('path', ''))} → {basename(e.get('new_path', ''))}"
    if t == "registry_set":
        return f"Registry set: {e.get('key', '')} [{e.get('value_name', '')}] = {str(e.get('data', ''))[:70]}"
    if t == "mutex_create":
        return f"Mutex created: {e.get('name', '')}"
    if t == "service_create":
        return f"Service created: {e.get('name', '')} → {e.get('image_path', '')}"
    if t == "scheduled_task":
        return f"Scheduled task: {e.get('name', '')} → {e.get('command', '')}"
    if t == "dns_query":
        return f"DNS query: {e.get('name', '')} → {', '.join(e.get('answers', [])) or 'no answer'}"
    if t == "net_connect":
        return f"Connection: {e.get('dst_ip', '')}:{e.get('dst_port', '')}/{e.get('proto', 'tcp')}"
    if t == "http_request":
        size = f" ({int(e['bytes_out']):,} B out)" if e.get("bytes_out") else ""
        return f"HTTP {e.get('method', 'GET')} {e.get('url', '')}{size}"
    return t


def process_tree(report: Dict[str, Any]) -> str:
    procs = [e for e in report["events"] if e["type"] == "process_create"]
    by_pid = {str(p.get("pid")): p for p in procs}
    children: Dict[str, List[Dict[str, Any]]] = {}
    roots: List[Dict[str, Any]] = []
    for p in procs:
        ppid = str(p.get("ppid"))
        if ppid in by_pid and ppid != str(p.get("pid")):
            children.setdefault(ppid, []).append(p)
        else:
            roots.append(p)
    lines: List[str] = []

    def label(p: Dict[str, Any]) -> str:
        cmd = " ".join(str(p.get("cmdline", "")).split())
        return f"{basename(p.get('image', '')) or '?'} (pid {p.get('pid')})  {cmd[:80]}"

    def walk(p: Dict[str, Any], prefix: str, last: bool, root: bool) -> None:
        lines.append(label(p) if root else f"{prefix}{'└─ ' if last else '├─ '}{label(p)}")
        kids = children.get(str(p.get("pid")), [])
        for i, k in enumerate(kids):
            walk(k, "" if root else prefix + ("   " if last else "│  "), i == len(kids) - 1, False)

    for r in roots:
        walk(r, "", True, True)
    return "\n".join(lines) if lines else "(no process events)"


def build_timeline(report: Dict[str, Any], detections: List[Detection], limit: int = 70) -> List[Dict[str, Any]]:
    """Events in time order; every event that triggered a detection is always kept."""
    tags: Dict[int, List[str]] = {}
    for d in detections:
        for idx in d.events:
            tags.setdefault(idx, []).append(d.id)
    rows = []
    for e in report["events"]:
        rows.append({"idx": e["idx"], "t": e["t"], "event": describe(e), "detections": tags.get(e["idx"], [])})
    flagged = [r for r in rows if r["detections"]]
    plain = [r for r in rows if not r["detections"]]
    keep = flagged + plain[: max(0, limit - len(flagged))]
    keep.sort(key=lambda r: r["idx"])
    return keep
