# Vulnerability: Mastodon-Defcon User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-defcon.yaml`)

## Description
Mastodon-Defcon user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://defcon.social/@{{user}}
```

