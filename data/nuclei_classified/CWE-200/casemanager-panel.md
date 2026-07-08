# Vulnerability: CaseManager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`casemanager-panel.yaml`)

## Description
CaseManager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

