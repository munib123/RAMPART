# Vulnerability: Mastodon-EU Voice User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-eu-voice.yaml`)

## Description
Mastodon-EU Voice user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://social.network.europa.eu/api/v1/accounts/lookup?acct={{user}}
```

