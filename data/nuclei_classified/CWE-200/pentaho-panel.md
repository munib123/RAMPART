# Vulnerability: Pentaho User Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pentaho-panel.yaml`)

## Description
Pentaho User Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pentaho/Login
```

