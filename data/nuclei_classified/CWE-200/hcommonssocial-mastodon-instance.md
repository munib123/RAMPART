# Vulnerability: Hcommons.social (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hcommonssocial-mastodon-instance.yaml`)

## Description
Hcommons.social (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hcommons.social/api/v1/accounts/lookup?acct={{user}}
```

