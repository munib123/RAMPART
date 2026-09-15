# Nuclei Template: WordPress Solid Security < 9.0.1 - Unauthenticated Login Page Disclosure
**Template ID:** wp-better-wp-security-login-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`wp-better-wp-security-login-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Solid Security (formerly iThemes Security/Better WP Security) plugin before 9.0.1 is vulnerable to login page disclosure. When the Hide Backend feature is enabled and comments require user registration, the secret login URL token is exposed in the HTML source via the itsec-hb-token parameter in the comment form login links.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/
```

## References
- https://wordpress.org/plugins/better-wp-security/
- https://wpscan.com/vulnerability/b7201fc1-d825-484f-aca9-ba14a968179b/
