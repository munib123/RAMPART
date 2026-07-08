# Vulnerability: Cisco ASA VPN Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-asa-panel.yaml`)

## Description
Cisco ASA VPN panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/+CSCOE+/logon.html
```

