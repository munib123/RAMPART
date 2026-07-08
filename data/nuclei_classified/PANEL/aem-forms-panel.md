# Vulnerability: Adobe Experience Manager Forms - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`aem-forms-panel.yaml`)

## Description
Adobe Experience Manager Forms was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/lc/libs/livecycle/core/content/login.html
```

