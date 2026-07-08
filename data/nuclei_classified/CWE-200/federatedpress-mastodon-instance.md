# Vulnerability: Federated.press (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`federatedpress-mastodon-instance.yaml`)

## Description
Federated.press (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://federated.press/api/v1/accounts/lookup?acct={{user}}
```

