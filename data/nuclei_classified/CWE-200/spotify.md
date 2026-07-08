# Vulnerability: Spotify User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`spotify.yaml`)

## Description
Spotify user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://open.spotify.com/user/{{user}}
```

