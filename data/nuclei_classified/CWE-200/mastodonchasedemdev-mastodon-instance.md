# Vulnerability: Mastodon.chasedem.dev (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodonchasedemdev-mastodon-instance.yaml`)

## Description
Mastodon.chasedem.dev (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mastodon.chasem.dev/api/v1/accounts/lookup?acct={{user}}
```

