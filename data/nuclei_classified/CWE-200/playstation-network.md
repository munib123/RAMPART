# Vulnerability: Playstation Network User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`playstation-network.yaml`)

## Description
Playstation Network user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://psnprofiles.com/xhr/search/users?q={{user}}
```

