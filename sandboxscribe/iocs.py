"""IOC extraction with noise filtering and defanging."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List
from urllib.parse import urlsplit

from .schema import basename

# RFC 5737 documentation ranges are treated as routable so the synthetic samples behave like real traffic.
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

# Domains an OS or a browser contacts on its own; reporting them as IOCs would be noise.
BENIGN_SUFFIXES = (
    "microsoft.com", "windowsupdate.com", "msftconnecttest.com", "msftncsi.com",
    "digicert.com", "live.com", "office.com", "office365.com", "windows.net",
    "bing.com", "msedge.net", "gstatic.com", "googleapis.com", "verisign.com",
    "symcb.com", "symcd.com", "globalsign.com", "letsencrypt.org",
)

EXEC_EXT = (".exe", ".dll", ".scr", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".lnk", ".jar")
USER_DIRS = ("\\appdata\\", "\\temp\\", "\\programdata\\", "\\users\\public\\", "\\downloads\\")


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.version == 6:
        return False
    return ip.is_global or any(ip in n for n in _DOC_NETS)


def is_benign_domain(name: str) -> bool:
    name = (name or "").lower().rstrip(".")
    return any(name == s or name.endswith("." + s) for s in BENIGN_SUFFIXES)


def defang(value: str) -> str:
    return re.sub(r"^http", "hxxp", value, flags=re.I).replace(".", "[.]")


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def extract(report: Dict[str, Any]) -> Dict[str, Any]:
    """Return deduplicated, noise-filtered indicators grouped by type."""
    sample = report["sample"]
    domains, ips, urls, mutexes, regs, dropped = {}, {}, {}, {}, {}, {}
    filtered = 0
    for e in report["events"]:
        t = e["type"]
        if t == "dns_query":
            name = (e.get("name") or "").lower().rstrip(".")
            if not name:
                continue
            if is_benign_domain(name):
                filtered += 1
                continue
            domains.setdefault(name, e["t"])
            for a in e.get("answers", []):
                if is_public_ip(a):
                    ips.setdefault(a, e["t"])
        elif t == "net_connect":
            ip = e.get("dst_ip", "")
            if is_public_ip(ip):
                ips.setdefault(ip, e["t"])
        elif t == "http_request":
            url = e.get("url", "")
            host = e.get("host") or _host(url)
            if host and is_benign_domain(host):
                filtered += 1
                continue
            if url:
                urls.setdefault(url, e["t"])
            if host and not re.fullmatch(r"[\d.]+", host):
                domains.setdefault(host.lower(), e["t"])
            elif host and is_public_ip(host):
                ips.setdefault(host, e["t"])
        elif t == "mutex_create" and e.get("name"):
            mutexes.setdefault(e["name"], e["t"])
        elif t == "registry_set":
            key = e.get("key", "")
            if re.search(r"\\(run|runonce|services|winlogon|image file execution options)\b", key, re.I):
                regs.setdefault((key, e.get("value_name", ""), str(e.get("data", ""))), e["t"])
        elif t == "file_write":
            path = e.get("path", "")
            low = path.lower()
            if low.endswith(EXEC_EXT) or e.get("sha256"):
                if any(d in low for d in USER_DIRS) or e.get("sha256"):
                    dropped.setdefault(path, (e["t"], e.get("sha256", "")))
    hashes = []
    for h in ("sha256", "md5", "sha1"):
        if sample.get(h):
            hashes.append({"type": h, "value": sample[h], "context": f"sample {sample.get('name', '')}".strip()})
    for path, (_, sha) in dropped.items():
        if sha:
            hashes.append({"type": "sha256", "value": sha, "context": f"dropped {basename(path)}"})
    return {
        "domains": sorted(domains),
        "ips": sorted(ips),
        "urls": sorted(urls),
        "mutexes": sorted(mutexes),
        "registry": [{"key": k, "value_name": v, "data": d} for (k, v, d) in regs],
        "dropped_files": [{"path": p, "sha256": s} for p, (_, s) in dropped.items()],
        "hashes": hashes,
        "filtered_noise": filtered,
    }


def flatten(iocs: Dict[str, Any]) -> List[Dict[str, str]]:
    """One row per indicator for CSV export / TIP import."""
    rows: List[Dict[str, str]] = []
    for h in iocs["hashes"]:
        rows.append({"type": h["type"], "value": h["value"], "defanged": h["value"], "context": h["context"]})
    for d in iocs["domains"]:
        rows.append({"type": "domain", "value": d, "defanged": defang(d), "context": "contacted"})
    for i in iocs["ips"]:
        rows.append({"type": "ip", "value": i, "defanged": defang(i), "context": "contacted"})
    for u in iocs["urls"]:
        rows.append({"type": "url", "value": u, "defanged": defang(u), "context": "requested"})
    for m in iocs["mutexes"]:
        rows.append({"type": "mutex", "value": m, "defanged": m, "context": "created"})
    for r in iocs["registry"]:
        rows.append({"type": "registry", "value": r["key"] + (f" [{r['value_name']}]" if r["value_name"] else ""),
                     "defanged": r["key"], "context": f"data={r['data']}"})
    for f in iocs["dropped_files"]:
        rows.append({"type": "file", "value": f["path"], "defanged": f["path"], "context": "dropped"})
    return rows
