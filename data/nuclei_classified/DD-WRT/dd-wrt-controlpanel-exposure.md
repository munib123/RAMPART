# Vulnerability: DD-WRT Control Panel - Exposure
**Classification:** DD-WRT
**Source:** Nuclei Template (`dd-wrt-controlpanel-exposure.yaml`)

## Description
The DD-WRT web interface was found exposed without proper access controls, potentially allowing unauthorized users to view.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

