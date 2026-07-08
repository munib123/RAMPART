# Vulnerability: Cisco TelePresence MCU Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-telepresence-mcu-panel.yaml`)

## Description
Cisco TelePresence MCU login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

