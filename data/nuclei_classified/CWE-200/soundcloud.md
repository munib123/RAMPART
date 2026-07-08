# Vulnerability: SoundCloud User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`soundcloud.yaml`)

## Description
SoundCloud user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://soundcloud.com/{{user}}
```

