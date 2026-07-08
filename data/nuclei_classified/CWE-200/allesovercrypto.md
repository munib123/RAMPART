# Vulnerability: Allesovercrypto User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`allesovercrypto.yaml`)

## Description
Allesovercrypto user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://allesovercrypto.nl/user/{{user}}
```

