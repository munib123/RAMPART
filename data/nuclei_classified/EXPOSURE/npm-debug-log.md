# Vulnerability: NPM Debug Log Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`npm-debug-log.yaml`)

## Description
NPM Debug log file exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/npm-debug.log
GET {{BaseURL}}/assets/npm-debug.log
```

