# Vulnerability: AutomationDirect Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`automation-direct.yaml`)

## Description
AutomationDirect panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.html
```

