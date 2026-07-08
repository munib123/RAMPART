# Vulnerability: Game debate User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`game-debate.yaml`)

## Description
Game debate user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.game-debate.com/profile/{{user}}
```

