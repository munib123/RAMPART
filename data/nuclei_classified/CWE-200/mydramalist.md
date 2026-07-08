# Vulnerability: MyDramaList User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mydramalist.yaml`)

## Description
MyDramaList user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.mydramalist.com/profile/{{user}}
```

