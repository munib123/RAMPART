# Vulnerability: D-Link Wireless Router Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`d-link-wireless.yaml`)

## Description
D-Link Wireless Router panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/status.php
```

