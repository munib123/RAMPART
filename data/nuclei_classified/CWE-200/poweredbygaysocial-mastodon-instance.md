# Vulnerability: Poweredbygay.social (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`poweredbygaysocial-mastodon-instance.yaml`)

## Description
Poweredbygay.social (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://poweredbygay.social/api/v1/accounts/lookup?acct={{user}}
```

