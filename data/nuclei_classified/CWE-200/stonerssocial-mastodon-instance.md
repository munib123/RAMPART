# Vulnerability: Stoners.social (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`stonerssocial-mastodon-instance.yaml`)

## Description
Stoners.social (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://stoners.social/api/v1/accounts/lookup?acct={{user}}
```

