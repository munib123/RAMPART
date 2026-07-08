# Vulnerability: Threads User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`threads.yaml`)

## Description
Threads user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.threads.com/@{{user}}
```

