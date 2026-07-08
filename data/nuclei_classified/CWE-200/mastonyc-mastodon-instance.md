# Vulnerability: Masto.nyc (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastonyc-mastodon-instance.yaml`)

## Description
Masto.nyc (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://masto.nyc/api/v1/accounts/lookup?acct={{user}}
```

