# Vulnerability: Tenable Nessus Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nessus-panel.yaml`)

## Description
Tenable Nessus panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/server/status
```

