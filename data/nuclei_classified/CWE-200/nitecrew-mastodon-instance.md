# Vulnerability: Nitecrew (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nitecrew-mastodon-instance.yaml`)

## Description
Nitecrew (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://nitecrew.rip/api/v1/accounts/lookup?acct={{user}}
```

