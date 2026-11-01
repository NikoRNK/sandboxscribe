# Input schema

SandboxScribe consumes one normalized JSON document. Any sandbox can be reduced
to it; a built-in adapter converts **Sysmon JSON exports** automatically (the
CLI auto-detects the format).

```jsonc
{
  "sample": {
    "name": "Invoice_2025-10.docm", "sha256": "…", "md5": "…", "sha1": "…",
    "size": 48213, "file_type": "Word document with macros"
  },
  "environment": {
    "sandbox": "isolated VM + Sysmon", "os": "Windows 10 22H2 x64",
    "duration_s": 180, "network": "simulated internet, no real egress"
  },
  "events": [ { "t": 8.4, "type": "process_create", "…": "…" } ]
}
```

`t` is seconds since detonation start. Events are sorted by `t` (stable).
Unknown extra fields are preserved and ignored.

## Event types

| `type` | Fields (besides `t`, `pid`) |
|--------|------------------------------|
| `process_create` | `ppid`, `image`, `cmdline`, `parent_image`, `sha256` |
| `process_inject` | `target_pid`, `target_image` |
| `process_access` | `image`, `target_image`, `access` |
| `file_write` | `path`, `sha256`, `image` |
| `file_read` | `path`, `image` |
| `file_delete` | `path` |
| `file_rename` | `path`, `new_path` |
| `registry_set` | `key`, `value_name`, `data` |
| `mutex_create` | `name` |
| `service_create` | `name`, `image_path` |
| `scheduled_task` | `name`, `command` |
| `dns_query` | `name`, `answers` (list of IPs) |
| `net_connect` | `dst_ip`, `dst_port`, `proto` |
| `http_request` | `method`, `url`, `host`, `bytes_out` |

## Sysmon adapter (`sysmon.py`)

Accepts a JSON array or one JSON object per line (NDJSON); nested `System` /
`EventData` objects are flattened automatically.

| Sysmon EventID | Becomes |
|---|---|
| 1 Process create | `process_create` (with SHA-256 from `Hashes`) |
| 3 Network connect | `net_connect` |
| 8 CreateRemoteThread | `process_inject` |
| 10 ProcessAccess | `process_access` |
| 11 File create | `file_write` |
| 13 Registry value set | `registry_set` |
| 22 DNS query | `dns_query` (IPv4 answers extracted from `QueryResults`) |
| 23 File delete | `file_delete` |

Times are converted to seconds since the first event. Provide the sample's
identity with `--sample-name` / `--sample-sha256`.
