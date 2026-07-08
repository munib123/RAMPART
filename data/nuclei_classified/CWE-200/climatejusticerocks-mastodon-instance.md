# Vulnerability: Climatejustice.rocks (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`climatejusticerocks-mastodon-instance.yaml`)

## Description
Climatejustice.rocks (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://climatejustice.rocks/api/v1/accounts/lookup?acct={{user}}
```

