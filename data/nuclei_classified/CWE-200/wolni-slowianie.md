# Vulnerability: Wolni Słowianie User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wolni-slowianie.yaml`)

## Description
Wolni Słowianie user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://wolnislowianie.pl/{{user}}
```

