# Vulnerability: Pettingzoo.co (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pettingzooco-mastodon-instance.yaml`)

## Description
Pettingzoo.co (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pettingzoo.co/api/v1/accounts/lookup?acct={{user}}
```

