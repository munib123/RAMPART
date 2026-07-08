# Vulnerability: ChurchCRM Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`churchcrm-panel.yaml`)

## Description
ChurchCRM panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/session/begin
```

