# Vulnerability: IFTTT User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ifttt.yaml`)

## Description
IFTTT user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ifttt.com/p/{{user}}
```

