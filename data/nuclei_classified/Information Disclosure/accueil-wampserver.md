# Nuclei Template: Accueil WAMPSERVER Configuration Page - Detect
**Template ID:** accueil-wampserver
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`accueil-wampserver.yaml`)

## Vulnerability Information & PoC

## Description
Accueil WAMPSERVER configuration page was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## Remediation
Restrict access to the WAMP server configuration page and sub-tools.

## References
- https://www.wampserver.com/
