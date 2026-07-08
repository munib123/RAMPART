# Vulnerability: Scrutinizer Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`scrutinizer-config.yaml`)

## Description
Scrutinizer configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.scrutinizer.yml
```

