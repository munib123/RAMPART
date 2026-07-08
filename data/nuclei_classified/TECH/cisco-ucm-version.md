# Vulnerability: Cisco Unified Communications Manager - Detect
**Classification:** TECH
**Source:** Nuclei Template (`cisco-ucm-version.yaml`)

## Description
Detected the presence of the Cisco Unified Communications User Management portal.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cucm-uds/version
```

