# Vulnerability: TurnKey OpenVPN Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`turnkey-openvpn.yaml`)

## Description
TurnKey OpenVPN panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

