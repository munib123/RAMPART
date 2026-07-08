# Vulnerability: Fosstodon.org (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fosstodonorg-mastodon-instance.yaml`)

## Description
Fosstodon.org (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://fosstodon.org/api/v1/accounts/lookup?acct={{user}}
```

