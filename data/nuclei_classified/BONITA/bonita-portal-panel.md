# Vulnerability: Bonita Portal Login - Detect
**Classification:** BONITA
**Source:** Nuclei Template (`bonita-portal-panel.yaml`)

## Description
Detects the presence of Bonita Portal login page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/bonita/login.jsp
```

