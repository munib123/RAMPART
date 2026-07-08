# Vulnerability: Homarr Dashboard - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`homarr-panel.yaml`)

## Description
Homarr dashboard panel was detected. Homarr is a self-hosted dashboard for managing homelab and *arr-stack services.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

