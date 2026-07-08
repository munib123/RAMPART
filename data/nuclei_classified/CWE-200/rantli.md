# Vulnerability: Rant.li User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rantli.yaml`)

## Description
Rant.li user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.rant.li/{{user}}/
```

