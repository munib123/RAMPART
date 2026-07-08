# Vulnerability: Dell BMC Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dell-bmc-panel-detect.yaml`)

## Description
Dell BMC web panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

