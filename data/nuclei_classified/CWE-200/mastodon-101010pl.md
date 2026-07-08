# Vulnerability: Mastodon-101010.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-101010pl.yaml`)

## Description
Mastodon-101010.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://101010.pl/@{{user}}
```

