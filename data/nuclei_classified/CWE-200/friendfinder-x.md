# Vulnerability: FriendFinder-X User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`friendfinder-x.yaml`)

## Description
FriendFinder-X user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.friendfinder-x.com/profile/{{user}}
```

