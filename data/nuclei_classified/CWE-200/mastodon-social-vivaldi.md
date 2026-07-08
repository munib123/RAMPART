# Vulnerability: Mastodon-social vivaldi User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-social-vivaldi.yaml`)

## Description
Mastodon-social vivaldi user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://social.vivaldi.net/@{{user}}
```

