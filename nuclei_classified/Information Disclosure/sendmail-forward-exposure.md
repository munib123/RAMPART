# Nuclei Template: Sendmail .forward File - Exposure
**Template ID:** sendmail-forward-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-200
**Source:** Nuclei Template (`sendmail-forward-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Sendmail .forward file is publicly accessible. This file is used to configure email forwarding and can expose sensitive information including email addresses, forwarding rules, and potentially executable commands (pipe to programs).

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.forward
```

## References
- https://www.sendmail.org/~ca/email/doc8.12/op-sh-4.html
- https://linux.die.net/man/5/forward
