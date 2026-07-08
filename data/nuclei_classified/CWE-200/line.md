# Vulnerability: LINE User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`line.yaml`)

## Description
LINE user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://line.me/R/ti/p/@{{user}}?from=page
```

