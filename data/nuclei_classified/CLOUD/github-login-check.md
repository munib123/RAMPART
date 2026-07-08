# Vulnerability: Github Login Check
**Classification:** CLOUD
**Source:** Nuclei Template (`github-login-check.yaml`)

## Description
Checks for a valid github account.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://github.com/login HTTP/1.1
Host: github.com

POST https://github.com/session HTTP/1.1
Host: github.com
Origin: https://github.com
Content-Type: application/x-www-form-urlencoded
Referer: https://github.com/login

commit=Sign+in&authenticity_token={{authenticity_token}}&login={{username}}&password={{password}}&trusted_device=&webauthn-support=supported&webauthn-iuvpaa-support=unsupported&return_to=https%3A%2F%2Fgithub.com%2Flogin&allow_signup=&client_id=&integration=&required_field_34b7=&timestamp={{timestamp}}&timestamp_secret={{timestamp_secret}}
```

