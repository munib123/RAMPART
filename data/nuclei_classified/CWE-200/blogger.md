# Vulnerability: Blogger User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`blogger.yaml`)

## Description
Blogger user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.blogger.com/profile/{{user}}
```

