# Vulnerability: Mastodon-Chaos.social User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-chaossocial.yaml`)

## Description
Mastodon-Chaos.social user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://chaos.social/@{{user}}
```

