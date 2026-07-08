# Vulnerability: Drupal Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`drupal-login.yaml`)

## Description
Drupal login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/user/login
```

