# Nuclei Template: Psalm Configuration Exposure - Detect
**Template ID:** psalm-config
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-200
**Source:** Nuclei Template (`psalm-config.yaml`)

## Vulnerability Information & PoC

## Description
Psalm configuration page was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/psalm.xml
```

## References
- https://psalm.dev/docs/running_psalm/configuration/
