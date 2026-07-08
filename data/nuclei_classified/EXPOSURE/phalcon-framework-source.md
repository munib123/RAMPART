# Vulnerability: Phalcon Framework - Source Code Leakage
**Classification:** EXPOSURE
**Source:** Nuclei Template (`phalcon-framework-source.yaml`)

## Description
Phalcon Framework source code was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/anything_here
```

