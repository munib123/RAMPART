# Vulnerability: Steam User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`steam.yaml`)

## Description
Steam user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://steamcommunity.com/id/{{user}}
```

