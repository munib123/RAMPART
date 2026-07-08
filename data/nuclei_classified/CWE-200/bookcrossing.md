# Vulnerability: Bookcrossing User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bookcrossing.yaml`)

## Description
Bookcrossing user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.bookcrossing.com/mybookshelf/{{user}}
```

