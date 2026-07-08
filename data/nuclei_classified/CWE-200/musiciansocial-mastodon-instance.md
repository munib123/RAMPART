# Vulnerability: Musician.social (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`musiciansocial-mastodon-instance.yaml`)

## Description
Musician.social (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://musician.social/api/v1/accounts/lookup?acct={{user}}
```

