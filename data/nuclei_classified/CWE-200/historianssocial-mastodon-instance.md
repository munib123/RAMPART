# Vulnerability: Historians.social (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`historianssocial-mastodon-instance.yaml`)

## Description
Historians.social (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://historians.social/api/v1/accounts/lookup?acct={{user}}
```

