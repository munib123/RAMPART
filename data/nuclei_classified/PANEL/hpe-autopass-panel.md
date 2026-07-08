# Vulnerability: HPE AutoPass License Server - Panel Detection
**Classification:** PANEL
**Source:** Nuclei Template (`hpe-autopass-panel.yaml`)

## Description
Detected an exposed HPE AutoPass License Server web interface on the default HTTPS port (5814) by probing the /autopass endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/autopass
GET https://{{Host}}:5814/autopass
GET https://{{Host}}:5814/autopass/
```

