# Vulnerability: Mastodon-meow.social User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-meowsocial.yaml`)

## Description
Mastodon-meow.social user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://meow.social/@{{user}}
```

