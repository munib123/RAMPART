# Vulnerability: Mmorpg User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mmorpg.yaml`)

## Description
Mmorpg user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://forums.mmorpg.com/profile/{{user}}
```

