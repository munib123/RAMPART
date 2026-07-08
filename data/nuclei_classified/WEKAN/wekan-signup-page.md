# Vulnerability: Wekan Sign Up Page - Exposure
**Classification:** WEKAN
**Source:** Nuclei Template (`wekan-signup-page.yaml`)

## Description
Detected exposed Wekan sign-up functionality, indicating that unauthenticated users could access the registration page and potentially create new accounts.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sign-up
```

