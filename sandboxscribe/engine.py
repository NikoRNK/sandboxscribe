"""Pipeline: events -> detections -> verdict -> IOCs -> containment -> Sigma -> report data."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from . import __version__
from .containment import recommend
from .iocs import extract, flatten
from .rules import TACTIC_ORDER, run_rules
from .sigma import generate
from .timeline import build_timeline, process_tree

NONE_LABEL = "NO MALICIOUS BEHAVIOUR OBSERVED"


def _verdict(detections, duration_s: float, intel: Dict[str, Any]):
    score = min(100, sum(d.weight for d in detections))
    tactics = {d.tactic for d in detections}
    label = "MALICIOUS" if score >= 60 else "SUSPICIOUS" if score >= 25 else NONE_LABEL
    vt = intel.get("virustotal", {})
    mb = intel.get("malwarebazaar", {})
    confirmed = (vt.get("status") == "ok" and (vt.get("malicious", 0) or 0) >= 10) or bool(mb.get("signature"))
    if confirmed and label != "MALICIOUS":
        label = "MALICIOUS"
    if label == "MALICIOUS":
        confidence = "HIGH" if (len(tactics) >= 3 or confirmed) else "MEDIUM"
    elif label == "SUSPICIOUS":
        confidence = "MEDIUM" if len(tactics) >= 2 else "LOW"
    else:
        confidence = "LOW" if duration_s < 60 else "MEDIUM"
    return label, confidence, score, confirmed


def analyze(report: Dict[str, Any], vt=None, mb=None, author: str = "SandboxScribe") -> Dict[str, Any]:
    sample = report["sample"]
    detections = run_rules(report)
    intel: Dict[str, Any] = {}
    if sample.get("sha256"):
        if vt:
            intel["virustotal"] = vt.lookup(sample["sha256"])
        if mb:
            intel["malwarebazaar"] = mb.lookup(sample["sha256"])
    label, confidence, score, confirmed = _verdict(detections, float(report["environment"].get("duration_s") or 0), intel)
    iocs = extract(report)
    by_tactic: Dict[str, list] = {}
    for d in detections:
        by_tactic.setdefault(d.tactic, []).append(d)
    return {
        "tool": f"sandboxscribe {__version__}",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "sample": sample,
        "environment": report["environment"],
        "verdict": label,
        "confidence": confidence,
        "score": score,
        "intel_confirmed": confirmed,
        "intel": intel,
        "detections": [asdict(d) for d in detections],
        "tactics": [t for t in TACTIC_ORDER if t in by_tactic],
        "techniques": sorted({(d.technique, d.technique_name) for d in detections if d.technique}),
        "process_tree": process_tree(report),
        "timeline": build_timeline(report, detections),
        "iocs": iocs,
        "ioc_rows": flatten(iocs),
        "containment": recommend(report, detections, iocs, label),
        "sigma": generate(report, detections, iocs, author=author),
        "event_count": len(report["events"]),
    }
