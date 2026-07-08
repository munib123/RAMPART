# Vulnerability: Hometech.social (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hometechsocial-mastodon-instance.yaml`)

## Description
Hometech.social (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hometech.social/api/v1/accounts/lookup?acct={{user}}
```

