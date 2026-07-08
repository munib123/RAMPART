# Vulnerability: Nginx Proxy Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nginx-proxy-manager.yaml`)

## Description
Nginx Proxy Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

