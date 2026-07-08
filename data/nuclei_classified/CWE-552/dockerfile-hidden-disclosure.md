# Vulnerability: Dockerfile - Detect
**Classification:** CWE-552
**Source:** Nuclei Template (`dockerfile-hidden-disclosure.yaml`)

## Description
Dockerfile was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.dockerfile
GET {{BaseURL}}/.Dockerfile
GET {{BaseURL}}/Dockerfile
```

