# Vulnerability: Lor.sh (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`lorsh-mastodon-instance.yaml`)

## Description
Lor.sh (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://lor.sh/api/v1/accounts/lookup?acct={{user}}
```

