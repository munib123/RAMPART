# Vulnerability: Our Freedom Book User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`our-freedom-book.yaml`)

## Description
Our Freedom Book user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.ourfreedombook.com/{{user}}
```

