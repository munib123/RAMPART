# Vulnerability: Vkl.world (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vklworld-mastodon-instance.yaml`)

## Description
Vkl.world (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://vkl.world/api/v1/accounts/lookup?acct={{user}}
```

