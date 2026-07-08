# Vulnerability: Mastodon-mastodon User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-mastodon.yaml`)

## Description
Mastodon-mastodon user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mastodon.social/@{{user}}
```

