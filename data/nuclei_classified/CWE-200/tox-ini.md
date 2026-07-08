# Vulnerability: Tox Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tox-ini.yaml`)

## Description
Tox configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/tox.ini
```

