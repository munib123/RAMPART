# Vulnerability: QlikView AccessPoint Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`qlikview-accesspoint-panel.yaml`)

## Description
QlikView AccessPoint login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/qlikview/FormLogin.htm
```

