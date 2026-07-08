# Vulnerability: Guardfile Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`guard-config.yaml`)

## Description
Guardfile configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Guardfile
```

