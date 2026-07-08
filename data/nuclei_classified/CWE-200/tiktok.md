# Vulnerability: TikTok User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tiktok.yaml`)

## Description
TikTok user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.tiktok.com/oembed?url=https://www.tiktok.com/@{{user}}
```

