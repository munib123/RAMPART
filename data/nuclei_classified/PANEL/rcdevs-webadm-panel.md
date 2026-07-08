# Vulnerability: RCDevs WebADM Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`rcdevs-webadm-panel.yaml`)

## Description
RCDevs WebADM Login Panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/webapps/index.php
GET {{BaseURL}}/websrvs/index.php
GET {{BaseURL}}/admin/login_uid.php
```

