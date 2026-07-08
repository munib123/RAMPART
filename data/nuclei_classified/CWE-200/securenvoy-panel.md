# Vulnerability: SecurEnvoy Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`securenvoy-panel.yaml`)

## Description
SecurEnvoy login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/secadmin/
GET {{BaseURL}}/securenvoy/
GET {{BaseURL}}/secenrol/
GET {{BaseURL}}/RDWeb
```

