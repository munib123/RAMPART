# Vulnerability: Cisco Secure Firewall Management Center - Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-firepower-panel.yaml`)

## Description
Cisco Secure Firewall Management Center login panel was detected. Secure Firewall Management Center was formerly known as Firepower Management Center.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/login
```

