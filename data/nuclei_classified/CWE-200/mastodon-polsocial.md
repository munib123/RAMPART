# Vulnerability: Mastodon-pol.social User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-polsocial.yaml`)

## Description
Mastodon-pol.social user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pol.social/@{{user}}
```

