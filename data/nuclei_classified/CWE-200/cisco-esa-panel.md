# Vulnerability: Cisco Email Security Appliance - Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-esa-panel.yaml`)

## Description
Detected Cisco Email Security Appliance login panel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

