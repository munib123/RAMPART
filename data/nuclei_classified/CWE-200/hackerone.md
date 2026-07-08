# Vulnerability: HackerOne User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hackerone.yaml`)

## Description
HackerOne user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hackerone.com/{{user}}
```

