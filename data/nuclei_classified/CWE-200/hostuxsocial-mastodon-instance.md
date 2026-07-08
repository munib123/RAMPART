# Vulnerability: Hostux.social (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hostuxsocial-mastodon-instance.yaml`)

## Description
Hostux.social (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hostux.social/api/v1/accounts/lookup?acct={{user}}
```

