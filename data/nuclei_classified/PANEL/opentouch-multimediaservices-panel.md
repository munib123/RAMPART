# Vulnerability: OpenTouch Multimedia Services - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`opentouch-multimediaservices-panel.yaml`)

## Description
OpenTouch Multimedia Services Login Panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/authenticationform/login
GET {{BaseURL}}/authenticationform/jsp/logonWeb.jsp
```

