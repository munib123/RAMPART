# Vulnerability: Mastodon-API User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-api.yaml`)

## Description
Mastodon-API user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mastodon.social/api/v2/search?q={{user}}
```

