# Nuclei Template: Reflected Odoo - Open Redirect
**Template ID:** odoo-login-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Low
**Source:** Nuclei Template (`odoo-login-redirect.yaml`)

## Vulnerability Information & PoC

## Description
Detected an open redirect vulnerability in Odoo where the redirect parameter in web/login was abused to redirect users to an attacker-controlled external URL after the authentication flow.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/web/login?db=asdf&redirect=http://interact.sh
```

## References
- https://github.com/odoo/odoo/issues/13812
