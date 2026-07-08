# Vulnerability: Tabletoptournament User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tabletoptournament.yaml`)

## Description
Tabletoptournament user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.tabletoptournaments.net/eu/player/{{user}}
```

