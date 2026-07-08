# Vulnerability: Policja2009 User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`policja2009.yaml`)

## Description
Policja2009 user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://www.policja2009.fora.pl/search.php?search_author={{user}}
```

