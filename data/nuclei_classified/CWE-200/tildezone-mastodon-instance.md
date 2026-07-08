# Vulnerability: Tilde.zone (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tildezone-mastodon-instance.yaml`)

## Description
Tilde.zone (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://tilde.zone/api/v1/accounts/lookup?acct={{user}}
```

