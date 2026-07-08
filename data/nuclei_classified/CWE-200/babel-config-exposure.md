# Vulnerability: Babel Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`babel-config-exposure.yaml`)

## Description
Babel configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/babel.config.js
```

