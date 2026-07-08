# Vulnerability: Cookies without Secure attribute - Detect
**Classification:** CWE-614
**Source:** Nuclei Template (`cookies-without-secure.yaml`)

## Description
Checks whether cookies in the HTTP response contain the Secure attribute. If the Secure flag is set, it means that the cookie can only be transmitted over HTTPS

## Secure Mitigation
Ensure that all cookies are set with the Secure attribute to prevent MITM attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

