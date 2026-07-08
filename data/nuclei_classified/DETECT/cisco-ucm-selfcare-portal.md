# Vulnerability: Cisco Unified Communications Self-Service User Portal - Detection
**Classification:** DETECT
**Source:** Nuclei Template (`cisco-ucm-selfcare-portal.yaml`)

## Description
Detected the presence of the Cisco Unified Communications User Management Panel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ucmuser/
```

