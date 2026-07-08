# Vulnerability: BuzzFeed User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`buzzfeed.yaml`)

## Description
BuzzFeed user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.buzzfeed.com/{{user}}
```

