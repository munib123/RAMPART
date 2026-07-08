# Vulnerability: Giant Bomb User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`giant-bomb.yaml`)

## Description
Giant Bomb user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.giantbomb.com/profile/{{user}}/
```

