# Vulnerability: Expressional.social (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`expressionalsocial-mastodon-instance.yaml`)

## Description
Expressional.social (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://expressional.social/api/v1/accounts/lookup?acct={{user}}
```

