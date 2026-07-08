# Vulnerability: Prv.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`prvpl.yaml`)

## Description
Prv.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.prv.pl/osoba/{{user}}
```

