# Vulnerability: Cisco Secure Desktop Installation Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-secure-desktop.yaml`)

## Description
Cisco Secure Desktop installation panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/CACHE/sdesktop/install/start.htm
```

