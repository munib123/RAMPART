# Vulnerability: Zbiornik User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zbiornik.yaml`)

## Description
Zbiornik user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mini.zbiornik.com/{{user}}
```

