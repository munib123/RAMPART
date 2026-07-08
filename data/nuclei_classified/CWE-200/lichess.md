# Vulnerability: Lichess User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`lichess.yaml`)

## Description
Lichess user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://lichess.org/@/{{user}}
```

