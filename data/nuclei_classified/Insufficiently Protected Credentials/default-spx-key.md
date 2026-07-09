# Nuclei Template: SPX PHP Profiler - Default Key
**Template ID:** default-spx-key
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`default-spx-key.yaml`)

## Vulnerability Information & PoC

## Description
SPX PHP profiler default spx key were discovered.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?SPX_KEY={{api_key}}&SPX_UI_URI=/
```

## Remediation
- https://github.com/NoiseByNorthwest/php-spx#security-concern

## References
- https://github.com/NoiseByNorthwest/php-spx
