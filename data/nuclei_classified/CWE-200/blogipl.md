# Vulnerability: Blogi.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`blogipl.yaml`)

## Description
Blogi.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.blogi.pl/osoba,{{user}}.html
```

