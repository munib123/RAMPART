# Vulnerability: Fortinet FortiSIEM - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`fortisiem-panel.yaml`)

## Description
FortiSIEM login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/phoenix/login.html
```

