# Vulnerability: Ruckus Wireless Unleashed Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ruckus-unleashed-panel.yaml`)

## Description
Ruckus Wireless Unleashed login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login.jsp
```

