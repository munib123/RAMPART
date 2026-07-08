# Vulnerability: ScoutWiki User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`scoutwiki.yaml`)

## Description
ScoutWiki user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://en.scoutwiki.org/User:{{user}}
```

