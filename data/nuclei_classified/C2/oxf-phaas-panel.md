# Vulnerability: OXF Phishing as a Service Panel - Detect
**Classification:** C2
**Source:** Nuclei Template (`oxf-phaas-panel.yaml`)

## Description
OXF Phishing as a Service Panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

