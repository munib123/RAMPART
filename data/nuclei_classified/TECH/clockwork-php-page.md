# Vulnerability: Clockwork PHP page exposure
**Classification:** TECH
**Source:** Nuclei Template (`clockwork-php-page.yaml`)

## Description
Clockwork php page was exposed, which allows admins to profile and debug the application, view database queries, HTTP requests, and other details right from the browser's developer tools.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/__clockwork/app
```

