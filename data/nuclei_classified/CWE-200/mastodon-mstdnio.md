# Vulnerability: Mastodon-mstdn.io User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-mstdnio.yaml`)

## Description
Mastodon-mstdn.io user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mstdn.io/@{{user}}
```

