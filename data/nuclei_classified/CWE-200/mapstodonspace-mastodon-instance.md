# Vulnerability: Mapstodon.space (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mapstodonspace-mastodon-instance.yaml`)

## Description
Mapstodon.space (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mapstodon.space/api/v1/accounts/lookup?acct={{user}}
```

