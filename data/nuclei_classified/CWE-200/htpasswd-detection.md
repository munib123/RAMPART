# Vulnerability: Apache htpasswd Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`htpasswd-detection.yaml`)

## Description
Apache htpasswd configuration was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.htpasswd
```

