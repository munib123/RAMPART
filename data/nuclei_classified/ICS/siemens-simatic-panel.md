# Vulnerability: Siemens SIMATIC HMI Miniweb - Login Panel
**Classification:** ICS
**Source:** Nuclei Template (`siemens-simatic-panel.yaml`)

## Description
Siemens SIMATIC HMI Miniweb Login Panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/start.html
```

