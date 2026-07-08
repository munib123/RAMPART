# Vulnerability: phpspec Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`phpsec-config.yaml`)

## Description
phpspec configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.phpspec.yml
GET {{BaseURL}}/phpspec.yml
```

