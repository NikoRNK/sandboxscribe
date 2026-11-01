from sandboxscribe.rules import run_rules, shannon
from sandboxscribe.schema import SchemaError, normalize
import pytest


def rep(events, name="x.docm"):
    return normalize({"sample": {"name": name}, "events": events})


def ids(events, **kw):
    return {d.id for d in run_rules(rep(events, **kw))}


def test_office_shell():
    ev = [{"t": 1, "type": "process_create", "pid": 2, "image": "C:\\Windows\\System32\\cmd.exe",
           "parent_image": "C:\\Office\\WINWORD.EXE", "cmdline": "cmd /c whoami"}]
    assert "OFFICE_SPAWNS_SHELL" in ids(ev)


def test_normal_parent_not_flagged():
    ev = [{"t": 1, "type": "process_create", "pid": 2, "image": "C:\\Windows\\System32\\cmd.exe",
           "parent_image": "C:\\Windows\\explorer.exe", "cmdline": "cmd /c dir"}]
    assert ids(ev) == set()


def test_encoded_powershell():
    cmd = "powershell -nop -w hidden -enc " + "QUJD" * 8
    ev = [{"t": 1, "type": "process_create", "pid": 2, "image": "C:\\x\\powershell.exe", "cmdline": cmd}]
    assert {"PS_EVASIVE_FLAGS", "PS_ENCODED"} <= ids(ev)


def test_run_key_persistence():
    ev = [{"t": 1, "type": "registry_set", "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
           "value_name": "x", "data": "c:\\a.exe"}]
    assert "PERSIST_RUN_KEY" in ids(ev)


def test_inhibit_recovery_and_ransomware():
    ev = [{"t": 1, "type": "process_create", "pid": 2, "image": "C:\\Windows\\System32\\vssadmin.exe",
           "cmdline": "vssadmin delete shadows /all /quiet"}]
    ev += [{"t": 2 + i, "type": "file_rename", "path": f"C:\\Users\\a\\doc{i}.docx",
            "new_path": f"C:\\Users\\a\\doc{i}.docx.locked"} for i in range(25)]
    assert {"INHIBIT_RECOVERY", "MASS_ENCRYPTION"} <= ids(ev)


def test_lsass_access():
    ev = [{"t": 1, "type": "process_access", "image": "C:\\t\\x.exe", "target_image": "C:\\Windows\\System32\\lsass.exe",
           "access": "0x1410"}]
    assert "LSASS_ACCESS" in ids(ev)


def test_beaconing_regular_vs_random():
    regular = [{"t": 30 * i, "type": "http_request", "host": "c2.example", "url": "http://c2.example/g", "method": "POST"}
               for i in range(1, 7)]
    assert "C2_BEACONING" in ids(regular)
    irregular = [{"t": t, "type": "http_request", "host": "c2.example", "url": "http://c2.example/g", "method": "GET"}
                 for t in (3, 4, 40, 41, 200, 203)]
    assert "C2_BEACONING" not in ids(irregular)


def test_benign_noise_domain_ignored():
    ev = [{"t": i * 30, "type": "http_request", "host": "ctldl.windowsupdate.com", "url": "http://ctldl.windowsupdate.com/x",
           "method": "GET"} for i in range(1, 8)]
    assert ids(ev) == set()


def test_self_delete_and_sleep():
    ev = [{"t": 1, "type": "process_create", "pid": 2, "image": "C:\\Windows\\System32\\cmd.exe",
           "cmdline": "cmd /c ping -n 30 127.0.0.1 > nul"},
          {"t": 2, "type": "file_delete", "path": "C:\\Users\\a\\Desktop\\X.DOCM"}]
    assert {"TIME_BASED_EVASION", "SELF_DELETE"} <= ids(ev)


def test_entropy_helper():
    assert shannon("aaaa") == 0
    assert shannon("7x2k9qv4mz") > 3


def test_schema_rejects_garbage():
    with pytest.raises(SchemaError):
        normalize({"events": [{"no_type": 1}]})
    with pytest.raises(SchemaError):
        normalize([])
