"""From observed behaviour to a containment recommendation.

The output is tiered the way an incident handler thinks: stop the bleeding,
remove what the sample installed, hunt for siblings, recover, communicate.
Every line is derived from what the sample actually did - nothing generic is
emitted unless a behaviour justifies it.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .schema import basename


def recommend(report: Dict[str, Any], detections, iocs: Dict[str, Any], label: str) -> Dict[str, List[str]]:
    ids = {d.id for d in detections}
    sample = report["sample"]
    tiers: Dict[str, List[str]] = {"Immediate (stop the spread)": [], "Eradicate (remove what it installed)": [],
                                   "Hunt (find the siblings)": [], "Recover & communicate": []}
    imm, era, hunt, rec = tiers.values()

    if label == "NO MALICIOUS BEHAVIOUR OBSERVED":
        imm.append("No containment required on this evidence. Keep the report with the ticket.")
        hunt.append("Re-detonate with a longer runtime and user-interaction simulation before declaring the file safe: "
                    "absence of behaviour in a sandbox is not proof of benignity.")
        return tiers

    imm.append("Isolate every host that executed the sample (EDR network containment) and kill the process tree shown in the report.")
    if iocs["domains"] or iocs["ips"]:
        targets = ", ".join(iocs["domains"][:3] + iocs["ips"][:3])
        imm.append(f"Block at DNS / proxy / firewall: {targets}"
                   + (" (+ more, see IOC list)." if len(iocs["domains"]) + len(iocs["ips"]) > 6 else "."))
    if sample.get("sha256"):
        imm.append(f"Block the sample hash {sample['sha256'][:16]}… in EDR / mail gateway and purge the delivering message from all mailboxes.")
    if "OFFICE_SPAWNS_SHELL" in ids:
        imm.append("Disable macros from the internet (Mark-of-the-Web policy) until the delivery path is closed.")

    for r in iocs["registry"]:
        era.append(f"Delete registry persistence {r['key']}" + (f" value '{r['value_name']}'" if r["value_name"] else "")
                   + (f" (points to {r['data']})." if r["data"] else "."))
    if "PERSIST_SCHTASK" in ids:
        era.append("Delete the scheduled task(s) created by the sample (schtasks /delete) and review all tasks created in the window.")
    if "PERSIST_SERVICE" in ids:
        era.append("Stop and delete the service the sample created (sc delete) after capturing its binary.")
    for f in iocs["dropped_files"]:
        era.append(f"Remove dropped file {f['path']}" + (f" (sha256 {f['sha256'][:12]}…)." if f["sha256"] else "."))
    if "DEFENDER_TAMPER" in ids:
        era.append("Remove added Defender exclusions / re-enable real-time protection and verify tamper protection.")
    if "PROCESS_INJECTION" in ids:
        era.append("Memory-image the injected host before reboot: a clean-looking host process may still hold the payload. Reimage if in doubt.")

    hunt.append("Search EDR / SIEM for the sample hashes and dropped-file names across the whole fleet over the last 30 days.")
    if iocs["domains"] or iocs["ips"]:
        hunt.append("Search proxy / DNS / NetFlow history for the domains and IPs; each hit is a potentially compromised host.")
    if iocs["mutexes"]:
        hunt.append("Hunt for the mutex name(s) in EDR telemetry: they survive recompilation of the payload.")
    hunt.append("Deploy the generated Sigma rules (see sigma/) as detections, then back-test them on 30 days of logs.")
    if "C2_BEACONING" in ids:
        hunt.append("Look for periodic outbound traffic with the same interval/jitter from other hosts (beaconing analytics).")

    if "LSASS_ACCESS" in ids or "BROWSER_CRED_THEFT" in ids:
        rec.append("Assume credentials on the host are stolen: reset passwords, revoke sessions/tokens and rotate any secrets "
                   "stored in the browser or on the machine.")
    if "MASS_ENCRYPTION" in ids or "INHIBIT_RECOVERY" in ids:
        rec.append("Ransomware precursor/impact seen: restore from offline backups only after confirming the intrusion path is closed; "
                   "escalate to the major-incident process.")
    if "LARGE_UPLOAD" in ids:
        rec.append("Possible data exfiltration: determine what the process could read, and involve legal / DPO if personal data is in scope.")
    rec.append("Notify affected users, submit the sample to the AV vendor and share IOCs with trusted partners (ISAC / CERT).")
    rec.append("Record the case and update the detection backlog with every TTP that was not alerted on.")
    return tiers
