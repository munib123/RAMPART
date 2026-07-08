# Vulnerability: Discuss.social (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`discusssocial-mastodon-instance.yaml`)

## Description
Discuss.social (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://discuss.social/api/v1/accounts/lookup?acct={{user}}
```

