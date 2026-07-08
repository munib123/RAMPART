# Vulnerability: Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`config-json.yaml`)

## Description
Multiple configuration files were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config/default.json
GET {{BaseURL}}/config.json
GET {{BaseURL}}/config/config.json
GET {{BaseURL}}/credentials/config.json
```

