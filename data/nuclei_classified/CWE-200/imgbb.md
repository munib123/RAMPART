# Vulnerability: ImgBB User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`imgbb.yaml`)

## Description
ImgBB user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.imgbb.com
```

