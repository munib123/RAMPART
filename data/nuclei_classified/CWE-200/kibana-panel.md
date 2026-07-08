# Vulnerability: Kibana Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kibana-panel.yaml`)

## Description
Kibana login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
GET {{BaseURL}}/app/kibana
```

