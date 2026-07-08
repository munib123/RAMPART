# Vulnerability: ArmorGames User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`armorgames.yaml`)

## Description
ArmorGames user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://armorgames.com/user/{{user}}
```

