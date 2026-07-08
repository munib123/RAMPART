# Vulnerability: Open Web Analytics Login - Detect
**Classification:** OPEN-WEB-ANALYTICS
**Source:** Nuclei Template (`open-web-analytics-panel.yaml`)

## Description
Detects the presence of Open Web Analytics login page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?owa_do=base.loginForm
```

