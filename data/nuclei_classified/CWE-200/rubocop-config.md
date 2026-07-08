# Vulnerability: Rubocop Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rubocop-config.yaml`)

## Description
Rubocop configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.rubocop.yml
```

