# Vulnerability: Traefik Dashboard Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`traefik-dashboard.yaml`)

## Description
Traefik Dashboard panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dashboard/
```

