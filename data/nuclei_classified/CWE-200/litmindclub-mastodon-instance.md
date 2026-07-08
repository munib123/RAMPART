# Vulnerability: Litmind.club (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`litmindclub-mastodon-instance.yaml`)

## Description
Litmind.club (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://litmind.club/api/v1/accounts/lookup?acct={{user}}
```

