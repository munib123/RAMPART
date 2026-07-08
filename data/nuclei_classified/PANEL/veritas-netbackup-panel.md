# Vulnerability: Veritas NetBackup OpsCenter Analytics Login - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`veritas-netbackup-panel.yaml`)

## Description
A Veritas NetBackup OpsCenter Analytics page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/opscenter/
```

