# Vulnerability: Jackett UI - Unauthenticated
**Classification:** UNAUTH
**Source:** Nuclei Template (`jackett-unauth.yaml`)

## Description
The Jackett UI can be accessed without authentication, potentially exposing sensitive information and configuration settings to unauthorized users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/UI/Dashboard
GET {{BaseURL}}/jackett/UI/Dashboard
```

