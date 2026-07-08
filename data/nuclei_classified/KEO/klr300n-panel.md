# Vulnerability: KLR 300N Router Panel - Detect
**Classification:** KEO
**Source:** Nuclei Template (`klr300n-panel.yaml`)

## Description
Home router wireless KLR 300N login panel were Detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.asp
```

