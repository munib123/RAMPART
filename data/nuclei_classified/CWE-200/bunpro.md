# Vulnerability: Bunpro User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bunpro.yaml`)

## Description
Bunpro user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://community.bunpro.jp/u/{{user}}.json
```

