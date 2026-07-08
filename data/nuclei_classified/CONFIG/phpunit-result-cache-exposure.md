# Vulnerability: PHPUnit Result Cache File Exposure
**Classification:** CONFIG
**Source:** Nuclei Template (`phpunit-result-cache-exposure.yaml`)

## Description
PHPUnit cache file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.phpunit.result.cache
```

