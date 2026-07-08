# Vulnerability: Whatsup Gold Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`whatsup-gold-panel.yaml`)

## Description
Whatsup Gold login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/NmConsole
GET {{BaseURL}}
```

