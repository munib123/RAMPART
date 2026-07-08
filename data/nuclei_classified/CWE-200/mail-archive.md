# Vulnerability: The Mail Archive Information
**Classification:** CWE-200
**Source:** Nuclei Template (`mail-archive.yaml`)

## Description
Mail-archive information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.mail-archive.com/search?l=all&q={{user}}
```

