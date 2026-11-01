import json

from conftest import SAMPLES
from sandboxscribe.engine import analyze
from sandboxscribe.report import render_iocs_csv, render_json, render_markdown
from sandboxscribe.schema import load_report
from sandboxscribe.sysmon import convert, read_rows
from sandboxscribe.schema import normalize
from sandboxscribe.timeline import process_tree


def run(name):
    return analyze(load_report(str(SAMPLES / name)))


def test_dropper_is_malicious_with_full_chain():
    r = run("invoice_dropper_report.json")
    ids = {d["id"] for d in r["detections"]}
    assert r["verdict"] == "MALICIOUS" and r["confidence"] == "HIGH"
    assert {"OFFICE_SPAWNS_SHELL", "PS_ENCODED", "PERSIST_RUN_KEY", "PERSIST_SCHTASK", "DEFENDER_TAMPER",
            "PROCESS_INJECTION", "C2_BEACONING", "LARGE_UPLOAD", "BROWSER_CRED_THEFT", "SELF_DELETE"} <= ids
    assert {"Execution", "Persistence", "Command and Control", "Exfiltration"} <= set(r["tactics"])


def test_benign_installer_is_clean_and_noise_filtered():
    r = run("benign_installer_report.json")
    assert r["verdict"] == "NO MALICIOUS BEHAVIOUR OBSERVED"
    assert r["iocs"]["domains"] == [] and r["iocs"]["filtered_noise"] == 2


def test_iocs_exclude_os_noise_and_are_defanged():
    r = run("invoice_dropper_report.json")
    assert "settings-win.data.microsoft.com" not in r["iocs"]["domains"]
    rows = {(x["type"], x["defanged"]) for x in r["ioc_rows"]}
    assert ("ip", "203[.]0[.]113[.]45") in rows


def test_containment_is_specific_to_observed_behaviour():
    r = run("invoice_dropper_report.json")
    text = " ".join(i for tier in r["containment"].values() for i in tier)
    assert "WindowsUpdateHelper" in text and "svchost32.exe" in text and "Defender" in text
    assert "ransomware" not in text.lower()  # not claimed when not observed


def test_sigma_rules_generated_and_valid_shape():
    r = run("invoice_dropper_report.json")
    assert len(r["sigma"]) == 5
    for yml in r["sigma"].values():
        assert yml.startswith("title:") and "detection:" in yml and "condition: selection" in yml


def test_process_tree_nesting():
    tree = process_tree(load_report(str(SAMPLES / "invoice_dropper_report.json")))
    assert tree.splitlines()[0].startswith("winword.exe") and "└─ cmd.exe" in tree


def test_sysmon_adapter_end_to_end():
    rep = normalize(convert(read_rows(str(SAMPLES / "sysmon_export.ndjson")), sample={"name": "Scan_0912.js"}))
    r = analyze(rep)
    ids = {d["id"] for d in r["detections"]}
    assert {"DOWNLOAD_CRADLE", "PERSIST_RUN_KEY"} <= ids
    assert "198.51.100.77" in r["iocs"]["ips"]
    assert any(e["type"] == "dns_query" and e["answers"] == ["198.51.100.77"] for e in rep["events"])


def test_renderers():
    r = run("invoice_dropper_report.json")
    assert "## 3. Containment recommendation" in render_markdown(r)
    assert json.loads(render_json(r))["verdict"] == "MALICIOUS"
    assert render_iocs_csv(r).startswith("type,value,defanged")
