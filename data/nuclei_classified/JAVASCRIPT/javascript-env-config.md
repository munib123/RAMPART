# Vulnerability: JavaScript Environment Configuration - Detect
**Classification:** JAVASCRIPT
**Source:** Nuclei Template (`javascript-env-config.yaml`)

## Description
Multiple common JavaScript environment configuration files were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/env.js
GET {{BaseURL}}/env.development.js
GET {{BaseURL}}/env.production.js
GET {{BaseURL}}/env.test.js
GET {{BaseURL}}/env.dev.js
GET {{BaseURL}}/env.prod.js
```

