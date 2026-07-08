# Vulnerability: Reflected Odoo - Open Redirect
**Classification:** REDIRECT
**Source:** Nuclei Template (`odoo-login-redirect.yaml`)

## Description
Detected an open redirect vulnerability in Odoo where the redirect parameter in web/login was abused to redirect users to an attacker-controlled external URL after the authentication flow.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web/login?db=asdf&redirect=http://interact.sh
```

