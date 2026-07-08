# Vulnerability: ICTBroadcast Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`ictbroadcast-panel.yaml`)

## Description
ICTBroadcast login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login.php
```

