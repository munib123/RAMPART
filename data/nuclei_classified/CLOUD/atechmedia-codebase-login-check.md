# Vulnerability: Atechmedia/Codebase Login Check
**Classification:** CLOUD
**Source:** Nuclei Template (`atechmedia-codebase-login-check.yaml`)

## Description
Checks for a valid Atechmedia/Codebase account.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://identity.atechmedia.com/login HTTP/1.1
Host: identity.atechmedia.com
Referer: https://identity.atechmedia.com/login

POST https://identity.atechmedia.com/login HTTP/1.1
Host: identity.atechmedia.com
Origin: https://identity.atechmedia.com
Content-Type: application/x-www-form-urlencoded
Referer: https://identity.atechmedia.com/login

utf8=%E2%9C%93&authenticity_token={{url_encode(authenticity_token)}}&username={{username}}&password={{password}}&commit=Login
```

