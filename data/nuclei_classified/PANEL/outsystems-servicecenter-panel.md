# Vulnerability: OutSystems Service Center Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`outsystems-servicecenter-panel.yaml`)

## Description
OutSystems Service Center login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Login.aspx
GET {{BaseURL}}/ServiceCenter/Login.aspx
```

