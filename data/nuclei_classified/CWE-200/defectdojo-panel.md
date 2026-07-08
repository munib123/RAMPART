# Vulnerability: DefectDojo Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`defectdojo-panel.yaml`)

## Description
DefectDojo login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login?next=
```

