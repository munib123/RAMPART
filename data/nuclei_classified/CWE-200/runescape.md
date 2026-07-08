# Vulnerability: RuneScape User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`runescape.yaml`)

## Description
RuneScape user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://apps.runescape.com/runemetrics/app/overview/player/{{user}}
```

