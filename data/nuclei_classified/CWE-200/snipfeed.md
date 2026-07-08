# Vulnerability: Snipfeed User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`snipfeed.yaml`)

## Description
Snipfeed user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://snipfeed.co/{{user}}
```

