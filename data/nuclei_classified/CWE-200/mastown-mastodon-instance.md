# Vulnerability: Mas.town (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastown-mastodon-instance.yaml`)

## Description
Mas.town (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mas.town/api/v1/accounts/lookup?acct={{user}}
```

