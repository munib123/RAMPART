# Vulnerability: Internet Archive Account User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`internet-archive-account.yaml`)

## Description
Internet Archive Account user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://archive.org/details/@{{user}}
```

