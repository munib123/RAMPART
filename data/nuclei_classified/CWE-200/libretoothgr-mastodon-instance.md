# Vulnerability: Libretooth.gr (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`libretoothgr-mastodon-instance.yaml`)

## Description
Libretooth.gr (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://libretooth.gr/api/v1/accounts/lookup?acct={{user}}
```

