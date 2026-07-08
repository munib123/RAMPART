# Vulnerability: phpPgAdmin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`phppgadmin-panel.yaml`)

## Description
phpPgAdmin login ipanel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/phppgadmin/
```

