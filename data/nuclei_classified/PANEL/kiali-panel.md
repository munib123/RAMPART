# Vulnerability: Kiali - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`kiali-panel.yaml`)

## Description
kiali panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/kiali/api/status
GET {{BaseURL}}/kiali/
```

