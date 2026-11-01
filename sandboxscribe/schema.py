"""Normalized detonation-report schema and loader.

Any sandbox (ANY.RUN, CAPE, a hand-built VM with Sysmon...) can be reduced to
this one shape, so analysis, reporting and detection engineering are written
once. See docs/SCHEMA.md for the full field reference.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

KNOWN_TYPES = {
    "process_create", "process_inject", "process_access",
    "file_write", "file_read", "file_delete", "file_rename",
    "registry_set", "mutex_create", "service_create", "scheduled_task",
    "dns_query", "net_connect", "http_request",
}


class SchemaError(ValueError):
    """The input is not a usable detonation report."""


def basename(path: str) -> str:
    """Lower-cased file name of a Windows or POSIX path."""
    return (path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def normalize(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get("events"), list):
        raise SchemaError("report must be a JSON object with an 'events' list")
    sample = dict(data.get("sample") or {})
    for key in ("name", "sha256", "md5", "sha1", "file_type"):
        sample.setdefault(key, "")
    sample.setdefault("size", 0)
    env = dict(data.get("environment") or {})
    env.setdefault("sandbox", "unknown")
    env.setdefault("os", "unknown")
    env.setdefault("duration_s", 0)
    env.setdefault("network", "unknown")
    events: List[Dict[str, Any]] = []
    for i, raw in enumerate(data["events"]):
        if not isinstance(raw, dict) or "type" not in raw:
            raise SchemaError(f"event #{i} must be an object with a 'type'")
        ev = dict(raw)
        try:
            ev["t"] = float(ev.get("t", 0))
        except (TypeError, ValueError):
            raise SchemaError(f"event #{i} has a non-numeric 't'")
        events.append(ev)
    events.sort(key=lambda e: e["t"])  # stable: ties keep file order
    for idx, ev in enumerate(events):
        ev["idx"] = idx
    return {"sample": sample, "environment": env, "events": events}


def load_report(path: str) -> Dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SchemaError(f"invalid JSON: {exc}") from exc
    return normalize(data)
