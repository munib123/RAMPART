# Vulnerability: Cisco Finesse - Detect
**Classification:** TECH
**Source:** Nuclei Template (`cisco-finesse-detect.yaml`)

## Description
Detected Cisco Finesse application and extracted version information from multiple sources.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/desktop/assets/js/finesse.js
```

