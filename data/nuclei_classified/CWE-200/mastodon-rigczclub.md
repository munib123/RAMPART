# Vulnerability: Mastodon-rigcz.club User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-rigczclub.yaml`)

## Description
Mastodon-rigcz.club user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://rigcz.club/@{{user}}
```

