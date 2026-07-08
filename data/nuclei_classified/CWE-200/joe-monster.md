# Vulnerability: Joe Monster User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`joe-monster.yaml`)

## Description
Joe Monster user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://joemonster.org/bojownik/{{user}}
```

