# Nuclei Template: Shibboleth SSO - Open Redirect
**Template ID:** shibboleth-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`shibboleth-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
Shibboleth SSO contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/Shibboleth.sso/Logout?return=https://{{randstr}}.interact.sh
```

## Remediation
Set the redirectLimit option documented in the references.

## References
- https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions
