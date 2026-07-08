# Vulnerability: TIBCO Spotfire Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`tibco-spotfire-panel.yaml`)

## Description
TIBCO Spotfire login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/spotfire/login.html
```

