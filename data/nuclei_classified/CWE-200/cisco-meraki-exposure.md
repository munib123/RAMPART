# Vulnerability: Cisco Meraki Cloud Security Appliance Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-meraki-exposure.yaml`)

## Description
Cisco Meraki Cloud Security Appliance panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#connection
```

