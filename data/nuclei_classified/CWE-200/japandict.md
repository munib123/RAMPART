# Vulnerability: Japandict User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`japandict.yaml`)

## Description
Japandict user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://forum.japandict.com/u/{{user}}
```

