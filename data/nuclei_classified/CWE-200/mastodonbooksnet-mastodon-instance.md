# Vulnerability: Mastodonbooks.net (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodonbooksnet-mastodon-instance.yaml`)

## Description
Mastodonbooks.net (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mastodonbooks.net/api/v1/accounts/lookup?acct={{user}}
```

