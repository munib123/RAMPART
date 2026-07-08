# Vulnerability: Magix User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`magix.yaml`)

## Description
Magix user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.magix.info/us/users/profile/{{user}}/
```

