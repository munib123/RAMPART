# Vulnerability: Procfile Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`procfile-config.yaml`)

## Description
Procfile configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Procfile
```

