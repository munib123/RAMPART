# Vulnerability: Monkeytype User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`monkeytype.yaml`)

## Description
Monkeytype user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://monkeytype.com/profile/{{user}}
```

