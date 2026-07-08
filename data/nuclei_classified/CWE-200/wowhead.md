# Vulnerability: Wowhead User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wowhead.yaml`)

## Description
Wowhead user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.wowhead.com/user={{user}}
```

