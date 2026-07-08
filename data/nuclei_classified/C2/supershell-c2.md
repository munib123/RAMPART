# Vulnerability: Supershell C2 - Detect
**Classification:** C2
**Source:** Nuclei Template (`supershell-c2.yaml`)

## Description
Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel, a fully interactive shell can be obtained, and it supports multi-platform architecture Payload.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

