# Vulnerability: BMC Remedy SSO Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`bmc-remedy-sso-panel.yaml`)

## Description
BMC Remedy Single Sign-On domain data entry login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/arsys/
GET {{BaseURL}}/webUI/userHome.do
```

