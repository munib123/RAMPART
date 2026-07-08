# Vulnerability: AMPPS Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`ampps-panel.yaml`)

## Description
An AMPPS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ampps/index.php?act=login
```

