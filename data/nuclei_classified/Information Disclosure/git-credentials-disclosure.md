# Nuclei Template: Git Credentials - Detect
**Template ID:** git-credentials-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`git-credentials-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Git credentials were detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.git-credentials
```

## References
- https://github.com/detectify/ugly-duckling/blob/master/modules/crowdsourced/git-credentials-disclosure.json
