# Vulnerability: OrangeHRM Login Panel - Detect
**Classification:** ORANGEHRM
**Source:** Nuclei Template (`orangehrm-panel.yaml`)

## Description
The OrangeHRM login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/symfony/web/index.php/auth/login
GET {{BaseURL}}/web/index.php/auth/login
```

