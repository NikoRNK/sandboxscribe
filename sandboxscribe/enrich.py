"""Optional hash enrichment: VirusTotal v3 and MalwareBazaar (abuse.ch).

LOOKUP ONLY. These clients ask what is already known about a hash; they never
download or upload a sample. Results are cached for 24 h.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional


class _Cached:
    def __init__(self, cache_dir: str, ttl: int = 86400) -> None:
        self.dir = Path(cache_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl

    def get(self, key: str) -> Optional[dict]:
        f = self.dir / (hashlib.sha1(key.encode()).hexdigest() + ".json")
        if f.exists() and time.time() - f.stat().st_mtime < self.ttl:
            return json.loads(f.read_text())
        return None

    def put(self, key: str, value: dict) -> None:
        (self.dir / (hashlib.sha1(key.encode()).hexdigest() + ".json")).write_text(json.dumps(value))


class VirusTotalHash(_Cached):
    API = "https://www.virustotal.com/api/v3/files/"

    def __init__(self, api_key: str, cache_dir: str = ".intel_cache", min_interval: float = 15.0) -> None:
        super().__init__(cache_dir)
        self.key, self.min_interval, self._last = api_key, min_interval, 0.0

    def lookup(self, sha256: str) -> Dict[str, Any]:
        if (hit := self.get("vt:" + sha256)) is not None:
            return hit
        wait = self.min_interval - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()
        req = urllib.request.Request(self.API + sha256, headers={"x-apikey": self.key, "accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                attrs = json.load(resp).get("data", {}).get("attributes", {})
        except urllib.error.HTTPError as exc:
            return {"source": "VirusTotal", "status": "unknown_to_vt" if exc.code == 404 else f"http_{exc.code}"}
        except (urllib.error.URLError, TimeoutError):
            return {"source": "VirusTotal", "status": "network_error"}
        stats = attrs.get("last_analysis_stats", {})
        result = {"source": "VirusTotal", "status": "ok", "malicious": stats.get("malicious", 0),
                  "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0),
                  "undetected": stats.get("undetected", 0),
                  "label": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", ""),
                  "permalink": f"https://www.virustotal.com/gui/file/{sha256}"}
        self.put("vt:" + sha256, result)
        return result


class MalwareBazaar(_Cached):
    API = "https://mb-api.abuse.ch/api/v1/"

    def __init__(self, auth_key: str, cache_dir: str = ".intel_cache") -> None:
        super().__init__(cache_dir)
        self.key = auth_key

    def lookup(self, sha256: str) -> Dict[str, Any]:
        if (hit := self.get("mb:" + sha256)) is not None:
            return hit
        data = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
        req = urllib.request.Request(self.API, data=data, headers={"Auth-Key": self.key})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = json.load(resp)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            return {"source": "MalwareBazaar", "status": "network_error"}
        if payload.get("query_status") != "ok":
            return {"source": "MalwareBazaar", "status": payload.get("query_status", "error")}
        row = (payload.get("data") or [{}])[0]
        result = {"source": "MalwareBazaar", "status": "ok", "signature": row.get("signature") or "",
                  "tags": row.get("tags") or [], "file_type": row.get("file_type", ""),
                  "first_seen": row.get("first_seen", ""),
                  "permalink": f"https://bazaar.abuse.ch/sample/{sha256}/"}
        self.put("mb:" + sha256, result)
        return result
