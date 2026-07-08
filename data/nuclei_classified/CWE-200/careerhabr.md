# Vulnerability: Career.habr User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`careerhabr.yaml`)

## Description
Career.habr user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://career.habr.com/{{user}}
```

