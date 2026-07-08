# Vulnerability: SPX PHP Profiler - Default Key
**Classification:** CWE-522
**Source:** Nuclei Template (`default-spx-key.yaml`)

## Description
SPX PHP profiler default spx key were discovered.

## Secure Mitigation
- https://github.com/NoiseByNorthwest/php-spx#security-concern

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?SPX_KEY={{api_key}}&SPX_UI_URI=/
```

