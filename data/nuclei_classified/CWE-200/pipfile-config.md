# Vulnerability: Pipfile Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pipfile-config.yaml`)

## Description
Pipfile configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Pipfile
```

