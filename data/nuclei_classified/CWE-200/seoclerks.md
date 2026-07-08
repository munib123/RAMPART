# Vulnerability: SEOClerks User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`seoclerks.yaml`)

## Description
SEOClerks user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.seoclerks.com/user/{{user}}
```

