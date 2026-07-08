# Vulnerability: WordPress Solid Security < 9.0.1 - Unauthenticated Login Page Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`wp-better-wp-security-login-disclosure.yaml`)

## Description
WordPress Solid Security (formerly iThemes Security/Better WP Security) plugin before 9.0.1 is vulnerable to login page disclosure. When the Hide Backend feature is enabled and comments require user registration, the secret login URL token is exposed in the HTML source via the itsec-hb-token parameter in the comment form login links.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

