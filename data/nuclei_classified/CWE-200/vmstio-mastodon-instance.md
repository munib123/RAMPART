# Vulnerability: Vmst.io (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vmstio-mastodon-instance.yaml`)

## Description
Vmst.io (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://vmst.io/api/v1/accounts/lookup?acct={{user}}
```

