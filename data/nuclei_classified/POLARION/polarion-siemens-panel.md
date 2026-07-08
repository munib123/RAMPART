# Vulnerability: Polarion Siemens Login - Panel
**Classification:** POLARION
**Source:** Nuclei Template (`polarion-siemens-panel.yaml`)

## Description
Detects the exposed Polarion Siemens login page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/polarion/
```

