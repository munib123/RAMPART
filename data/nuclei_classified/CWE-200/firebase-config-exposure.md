# Vulnerability: Firebase Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`firebase-config-exposure.yaml`)

## Description
Firebase configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/public/config.js
GET {{BaseURL}}/config.js
```

