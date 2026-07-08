# Vulnerability: Citrix VPN Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`citrix-vpn-detect.yaml`)

## Description
Citrix VPN panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/vpn/index.html
```

