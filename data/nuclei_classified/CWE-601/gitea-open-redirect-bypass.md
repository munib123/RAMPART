# Vulnerability: Gitea < 1.21.0 - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`gitea-open-redirect-bypass.yaml`)

## Description
Gitea before version 1.21.0 is affected by URL Redirection to Untrusted Site ('Open Redirect') via internal URLs. The vulnerability exists in the redirect_to parameter used on the login page (/user/login). Due to improper validation of the redirect URL, an attacker can craft a malicious link that redirects authenticated users to an arbitrary external website after login.

## Secure Mitigation
Upgrade Gitea to version 1.21.0 or later to fix the open redirect vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /user/login HTTP/1.1
Host: {{Hostname}}

POST /user/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: redirect_to={{redirect}}

_csrf={{csrf}}&user_name={{username}}&password={{url_encode(password)}}
```

