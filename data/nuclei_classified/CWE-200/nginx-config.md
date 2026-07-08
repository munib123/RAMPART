# Vulnerability: Nginx Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nginx-config.yaml`)

## Description
Nginx configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nginx.conf
```

