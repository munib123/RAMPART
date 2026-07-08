# Vulnerability: OpenVPN Connect Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`openvpn-connect.yaml`)

## Description
OpenVPN Connect panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?src=connect
```

