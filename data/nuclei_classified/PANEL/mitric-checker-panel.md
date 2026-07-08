# Vulnerability: Mitric Checker Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`mitric-checker-panel.yaml`)

## Description
Mitric Checker login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/QSA/Login.aspx
GET {{BaseURL}}/API/External/GetPrivacy
```

