# Vulnerability: Tooting.ch (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tootingch-mastodon-instance.yaml`)

## Description
Tooting.ch (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://tooting.ch/api/v1/accounts/lookup?acct={{user}}
```

