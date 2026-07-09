# Nuclei Template: OpenBMCS 2.4 - Information Disclosure
**Template ID:** openbmcs-secret-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`openbmcs-secret-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
OpenBMCS 2.4 contains an information disclosure vulnerability. The application allows directory listing and exposure of some sensitive files, which can allow an attacker to leverage the disclosed information and gain full access.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/debug/
```

## References
- https://www.exploit-db.com/exploits/50671
