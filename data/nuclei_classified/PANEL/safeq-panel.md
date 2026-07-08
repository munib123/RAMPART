# Vulnerability: YSoft SafeQ Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`safeq-panel.yaml`)

## Description
The YSoft SafeQ panel is umbrella printer management software used by many printer vendors. This should not be exposed to the public internet.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
```

