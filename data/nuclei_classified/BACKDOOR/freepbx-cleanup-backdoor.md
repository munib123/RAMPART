# Vulnerability: FreePBX - CVE-2025-57819 Backdoor
**Classification:** BACKDOOR
**Source:** Nuclei Template (`freepbx-cleanup-backdoor.yaml`)

## Description
FreePBX backdoor cleanup script used in 0-day exploitation of CVE-2025-57819 was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.clean.sh
```

