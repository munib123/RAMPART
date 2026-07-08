# Vulnerability: Cvent Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cvent-panel-detect.yaml`)

## Description
Cvent login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/Login.aspx
GET {{BaseURL}}/manager/login.aspx
GET {{BaseURL}}/GDSHost/Default.aspx
GET {{BaseURL}}/events/EventRsvp.aspx
```

