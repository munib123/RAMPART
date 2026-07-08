# Vulnerability: Web Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`web-config.yaml`)

## Description
Web configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web.config
GET {{BaseURL}}/../../web.config
```

