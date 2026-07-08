# Vulnerability: Rackup Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rackup-config-ru.yaml`)

## Description
Rackup configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config.ru
```

