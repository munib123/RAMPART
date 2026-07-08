# Vulnerability: Adult Forum User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`adult-forum.yaml`)

## Description
Adult Forum user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://adultforum.gr/{{user}}-glamour-escorts/
```

