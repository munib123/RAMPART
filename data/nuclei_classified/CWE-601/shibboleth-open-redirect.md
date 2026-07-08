# Vulnerability: Shibboleth SSO - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`shibboleth-open-redirect.yaml`)

## Description
Shibboleth SSO contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Secure Mitigation
Set the redirectLimit option documented in the references.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Shibboleth.sso/Logout?return=https://{{randstr}}.interact.sh
```

