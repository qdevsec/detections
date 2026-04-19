# Credential Dumping -- common post-exploitation behavior

1. Sample Logs

## Normal Behavior (Baseline)

{
  "timestamp": "2026-03-29T14:22:01Z",
  "event_id": 1,
  "user": "SYSTEM",
  "process_name": "svchost.exe",
  "command_line": "C:\\Windows\\system32\\svchost.exe -k LocalService",
  "parent_process": "services.exe"
}

## Suspicious Behavior (The "Signal")

{
  "timestamp": "2026-03-29T14:25:45Z",
  "event_id": 1,
  "user": "Admin-JS",
  "process_name": "procdump64.exe",
  "command_line": "procdump64.exe -ma lsass.exe C:\\temp\\lsass.dmp",
  "parent_process": "cmd.exe"
}

2. Behavoral Detection Logic

Detection Rule: LSASS Memory Access
- Logic: Trigger an alert when any process - other than known Windows binaries - accesses or creates a dump of the lsass.exe process memory

Query (SQL/KQL)

SELECT timestamp, user, command_line 
FROM process_logs
WHERE target_process = "lsass.exe"
AND command_line LIKE ANY ("%-ma%", "*-dump*", "*minidump*")
AND user NOT IN ("SYSTEM", "NETWORK SERVICE")