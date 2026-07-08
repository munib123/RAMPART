# Vulnerability: Setlist.fm User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`setlistfm.yaml`)

## Description
Setlist.fm user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.setlist.fm/user/{{user}}
```

