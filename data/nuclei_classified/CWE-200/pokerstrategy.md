# Vulnerability: Pokerstrategy User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pokerstrategy.yaml`)

## Description
Pokerstrategy user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://www.pokerstrategy.net/user/{{user}}/profile/
```

