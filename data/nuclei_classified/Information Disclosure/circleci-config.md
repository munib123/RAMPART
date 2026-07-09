# Nuclei Template: CircleCI Configuration File - Detect
**Template ID:** circleci-config
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`circleci-config.yaml`)

## Vulnerability Information & PoC

## Description
CircleCI config.yml file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.circleci/config.yml
```

## References
- https://circleci.com/docs/2.0/sample-config/
