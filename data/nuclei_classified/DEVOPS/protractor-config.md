# Vulnerability: Protractor Configuration Exposure
**Classification:** DEVOPS
**Source:** Nuclei Template (`protractor-config.yaml`)

## Description
Protractor configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/protractor.conf.js
```

