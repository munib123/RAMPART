# Vulnerability: Netdisco - Unauth Access
**Classification:** NETDISCO
**Source:** Nuclei Template (`netdisco-unauth.yaml`)

## Description
Detects an unauth dashboard access of Netdisco.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/inventory
```

