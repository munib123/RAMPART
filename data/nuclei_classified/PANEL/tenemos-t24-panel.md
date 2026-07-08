# Vulnerability: Tenemos T24 Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`tenemos-t24-panel.yaml`)

## Description
Tenemos T24 products was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/servlet/BrowserServlet
```

