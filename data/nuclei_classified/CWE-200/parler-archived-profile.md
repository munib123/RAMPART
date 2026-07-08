# Vulnerability: Parler archived profile User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`parler-archived-profile.yaml`)

## Description
Parler archived profile user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://archive.org/wayback/available?url=https://parler.com/profile/{{user}}
```

