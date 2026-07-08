# Vulnerability: Mastodon-climatejustice.rocks User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-climatejusticerocks.yaml`)

## Description
Mastodon-climatejustice.rocks user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://climatejustice.rocks/@{{user}}
```

