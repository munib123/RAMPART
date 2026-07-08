# Vulnerability: Oracle PeopleSoft Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`oracle-peoplesoft-panel.yaml`)

## Description
Oracle PeopleSoft login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/{{path}}
```

