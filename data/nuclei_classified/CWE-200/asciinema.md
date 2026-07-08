# Vulnerability: Asciinema User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`asciinema.yaml`)

## Description
Asciinema user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://asciinema.org/~{{user}}
```

