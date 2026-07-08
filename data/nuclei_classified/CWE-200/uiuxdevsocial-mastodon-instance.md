# Vulnerability: Uiuxdev.social (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`uiuxdevsocial-mastodon-instance.yaml`)

## Description
Uiuxdev.social (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://uiuxdev.social/api/v1/accounts/lookup?acct={{user}}
```

