# Vulnerability: Digital Watchdog - Detect
**Classification:** DIGITAL-WATCHDOG
**Source:** Nuclei Template (`digital-watchdog-panel.yaml`)

## Description
Digital Watchdog panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/static/images/favicon.ico
GET {{BaseURL}}/static/customization/favicon.ico
```

