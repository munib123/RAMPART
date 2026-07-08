# Vulnerability: PHPStan Configuration Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`phpstan-config.yaml`)

## Description
PHPStan configuration page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/phpstan.neon
```

