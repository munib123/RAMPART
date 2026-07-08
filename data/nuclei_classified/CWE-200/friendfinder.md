# Vulnerability: FriendFinder User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`friendfinder.yaml`)

## Description
FriendFinder user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://friendfinder.com/profile/{{user}}
```

