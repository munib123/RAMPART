# Vulnerability: Dot.cards User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dotcards.yaml`)

## Description
Dot.cards user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://dot.cards/{{user}}
```

