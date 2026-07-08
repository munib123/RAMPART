# Vulnerability: EMS Web Client Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ems-webclient-panel.yaml`)

## Description
EMS Web Client login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/emswebclient/Login.aspx
GET {{BaseURL}}/Login.aspx
```

