# Vulnerability: Cisco ACE 4710 Device Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-ace-4710-device-manager.yaml`)

## Description
Cisco ACE 4710 Device Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.vm
```

