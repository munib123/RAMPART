# Vulnerability: Cookies without HttpOnly attribute - Detect
**Classification:** CWE-1004
**Source:** Nuclei Template (`cookies-without-httponly.yaml`)

## Description
Checks whether cookies in the HTTP response contain the HttpOnly attribute. If the HttpOnly flag is set, it means that the cookie is HTTP-only

## Secure Mitigation
Ensure that all cookies are set with the HttpOnly attribute to prevent client-side access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

