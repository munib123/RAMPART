# Vulnerability: TotalWar User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`totalwar.yaml`)

## Description
TotalWar user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://forums.totalwar.com/profile/{{user}}
```

