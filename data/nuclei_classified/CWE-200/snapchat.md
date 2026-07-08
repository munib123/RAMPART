# Vulnerability: Snapchat User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`snapchat.yaml`)

## Description
Snapchat user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://feelinsonice.appspot.com/web/deeplink/snapcode?username={{user}}&size=400&type=SVG
```

