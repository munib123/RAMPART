# Vulnerability: Mastodon-Toot.Community User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-tootcommunity.yaml`)

## Description
Mastodon-Toot.Community user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://toot.community/@{{user}}
```

