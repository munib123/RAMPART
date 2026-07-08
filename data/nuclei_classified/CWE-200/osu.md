# Vulnerability: Osu! User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`osu.yaml`)

## Description
Osu! user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://osu.ppy.sh/users/{{user}}
```

