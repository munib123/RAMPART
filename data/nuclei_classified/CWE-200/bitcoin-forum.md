# Vulnerability: Bitcoin forum User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bitcoin-forum.yaml`)

## Description
Bitcoin forum user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://bitcoinforum.com/profile/{{user}}
```

