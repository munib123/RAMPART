# Nuclei Template: Dockerfile - Detect
**Template ID:** dockerfile-hidden-disclosure
**Vulnerability Class:** File and Directory Information Exposure
**Severity:** Medium
**CWE:** CWE-552
**Source:** Nuclei Template (`dockerfile-hidden-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Dockerfile was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.dockerfile
GET {{BaseURL}}/.Dockerfile
GET {{BaseURL}}/Dockerfile
```

## References
- https://github.com/detectify/ugly-duckling/blob/master/modules/crowdsourced/dockerfile-hidden-disclosure.json
