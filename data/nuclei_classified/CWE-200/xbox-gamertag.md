# Vulnerability: Xbox Gamertag User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xbox-gamertag.yaml`)

## Description
Xbox Gamertag user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.xboxgamertag.com/search/{{user}}
```

