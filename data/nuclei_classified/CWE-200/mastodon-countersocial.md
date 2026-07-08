# Vulnerability: Mastodon-counter.social User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-countersocial.yaml`)

## Description
Mastodon-counter.social user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://counter.social/@{{user}}
```

