"""Markdown / JSON / CSV rendering. Page one is written for the person who decides."""
from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List

from .rules import TACTIC_ORDER

ICON = {"MALICIOUS": "🔴", "SUSPICIOUS": "🟠", "NO MALICIOUS BEHAVIOUR OBSERVED": "🟢"}


def _esc(v: Any) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ")


def _table(headers: List[str], rows: List[List[Any]]) -> str:
    if not rows:
        return "_none_\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(_esc(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def _what_it_does(r: Dict[str, Any]) -> List[str]:
    """Top findings by weight, shown in chronological order (the story of the infection)."""
    top = sorted(r["detections"], key=lambda d: -d["weight"])[:7]
    top.sort(key=lambda d: d["t"])
    return [f"**{d['tactic']}** — {d['title']}. _{d['evidence']}_" for d in top]


def render_markdown(r: Dict[str, Any]) -> str:
    s, env, io_ = r["sample"], r["environment"], r["iocs"]
    L: List[str] = []
    L.append(f"# Malware Sandbox Report — {s.get('name') or 'unnamed sample'}\n")
    L.append(f"> **Generated:** {r['generated']} · **Tool:** {r['tool']} · **SHA-256:** `{s.get('sha256') or 'n/a'}`\n")

    # ---------------- page 1: the deliverable -----------------------
    L.append("## 1. Verdict\n")
    L.append(f"### {ICON.get(r['verdict'], '⚪')} {r['verdict']} — score {r['score']}/100 — confidence {r['confidence']}\n")
    if r["intel_confirmed"]:
        L.append("_Threat-intel lookup independently confirms this verdict._\n")
    if r["verdict"] == "NO MALICIOUS BEHAVIOUR OBSERVED":
        L.append("No rule fired in this detonation. A sandbox can only report what it **saw**: environment checks, "
                 "long sleeps or missing user interaction can hide behaviour. Treat as *not proven benign*.\n")
    else:
        L.append("## 2. What the sample does\n")
        L += [f"{n}. {line}" for n, line in enumerate(_what_it_does(r), 1)]
        L.append("")
    L.append("## 3. Containment recommendation\n")
    for tier, items in r["containment"].items():
        if items:
            L.append(f"**{tier}**\n")
            L += [f"- {i}" for i in items]
            L.append("")
    L.append("---\n")

    # ---------------- evidence --------------------------------------
    L.append("## 4. Sample & environment\n")
    L.append(_table(["Field", "Value"], [
        ["Name", s.get("name", "")], ["Type", s.get("file_type", "")], ["Size", f"{s.get('size', 0):,} bytes"],
        ["SHA-256", s.get("sha256", "")], ["SHA-1", s.get("sha1", "")], ["MD5", s.get("md5", "")],
        ["Sandbox", env.get("sandbox")], ["OS", env.get("os")], ["Runtime", f"{env.get('duration_s')} s"],
        ["Network mode", env.get("network")], ["Events analysed", r["event_count"]],
    ]))
    if r["intel"]:
        rows = []
        vt = r["intel"].get("virustotal")
        if vt:
            rows.append(["VirusTotal", vt.get("status"), f"{vt.get('malicious', '—')} malicious / {vt.get('undetected', '—')} undetected"
                         + (f" · {vt['label']}" if vt.get("label") else ""), vt.get("permalink", "")])
        mb = r["intel"].get("malwarebazaar")
        if mb:
            rows.append(["MalwareBazaar", mb.get("status"), f"{mb.get('signature', '—')} {mb.get('tags', '')}", mb.get("permalink", "")])
        L.append("### Threat-intel lookups\n")
        L.append(_table(["Source", "Status", "Result", "Link"], rows))

    L.append("## 5. Process tree\n")
    L.append("```text\n" + r["process_tree"] + "\n```\n")

    L.append("## 6. Behaviour timeline\n")
    L.append(_table(["T+ (s)", "Event", "Detections"],
                    [[f"{row['t']:.1f}", row["event"], ", ".join(row["detections"]) or ""] for row in r["timeline"]]))
    if len(r["timeline"]) < r["event_count"]:
        L.append(f"_Showing {len(r['timeline'])} of {r['event_count']} events: every event behind a detection is always kept._\n")

    L.append("## 7. Detections & MITRE ATT&CK\n")
    L.append(_table(["Weight", "Tactic", "Technique", "Finding", "Evidence"],
                    [[d["weight"], d["tactic"], f"{d['technique']} {d['technique_name']}".strip() or "—", d["title"], d["evidence"]]
                     for d in sorted(r["detections"], key=lambda x: -x["weight"])]))
    if r["tactics"]:
        L.append("**Kill-chain coverage:** " + " → ".join(f"**{t}**" if t in r["tactics"] else f"~~{t}~~" for t in TACTIC_ORDER) + "\n")

    L.append("## 8. Indicators of compromise (defanged)\n")
    rows = [[x["type"], x["defanged"], x["context"]] for x in r["ioc_rows"]]
    L.append(_table(["Type", "Value", "Context"], rows))
    if io_["filtered_noise"]:
        L.append(f"_{io_['filtered_noise']} OS / vendor noise indicators were filtered out (Microsoft update, certificate checks, …)._\n")

    if r["sigma"]:
        L.append("## 9. Detection rules generated (Sigma)\n")
        L.append("Written to `--sigma-dir`: " + ", ".join(f"`{n}`" for n in sorted(r["sigma"])) + "\n")
        name = sorted(r["sigma"])[0]
        L.append(f"Example — `{name}`:\n\n```yaml\n{r['sigma'][name]}```\n")
    return "\n".join(L)


def render_json(r: Dict[str, Any]) -> str:
    return json.dumps(r, indent=2, ensure_ascii=False, default=list)


def render_iocs_csv(r: Dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "defanged", "context", "sample_sha256", "verdict"])
    for x in r["ioc_rows"]:
        w.writerow([x["type"], x["value"], x["defanged"], x["context"], r["sample"].get("sha256", ""), r["verdict"]])
    return buf.getvalue()
