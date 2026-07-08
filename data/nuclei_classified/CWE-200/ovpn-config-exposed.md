# Vulnerability: OVPN Configuration Download Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ovpn-config-exposed.yaml`)

## Description
OVPS configuration download page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

