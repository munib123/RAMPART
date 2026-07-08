# Vulnerability: Mailpit App - Information Disclosure
**Classification:** MAILPIT
**Source:** Nuclei Template (`mailpit-app-info-disclosure.yaml`)

## Description
Mailpit exposes the /api/v1/messages endpoint which can leak email metadata or full email content without authentication, leading to information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/messages
```

