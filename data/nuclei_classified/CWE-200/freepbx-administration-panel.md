# Vulnerability: FreePBX Admin Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`freepbx-administration-panel.yaml`)

## Description
FreePBX admin panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/config.php
```

