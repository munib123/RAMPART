# Vulnerability: Disabled.rocks (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`disabledrocks-mastodon-instance.yaml`)

## Description
Disabled.rocks (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://disabled.rocks/api/v1/accounts/lookup?acct={{user}}
```

