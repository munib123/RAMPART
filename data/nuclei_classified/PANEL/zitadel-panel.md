# Vulnerability: ZITADEL Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`zitadel-panel.yaml`)

## Description
Detected ZITADEL was an open-source identity infrastructure platform providing OIDC, OAuth 2.0, SAML and machine-user IAM.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/console/
```

