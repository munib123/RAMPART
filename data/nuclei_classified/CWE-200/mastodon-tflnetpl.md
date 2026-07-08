# Vulnerability: Mastodon-tfl.net.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-tflnetpl.yaml`)

## Description
Mastodon-tfl.net.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://tfl.net.pl/@{{user}}
```

