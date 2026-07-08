# Vulnerability: Discogs User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`discogs.yaml`)

## Description
Discogs user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.discogs.com/user/{{user}}
```

