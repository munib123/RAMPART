# Vulnerability: Eset Protect Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`eset-protect-panel.yaml`)

## Description
Login page for Eset Protect

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/era/webconsole/
```

