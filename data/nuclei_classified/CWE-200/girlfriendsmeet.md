# Vulnerability: Girlfriendsmeet User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`girlfriendsmeet.yaml`)

## Description
Girlfriendsmeet user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://www.girlfriendsmeet.com/profile/{{user}}
```

