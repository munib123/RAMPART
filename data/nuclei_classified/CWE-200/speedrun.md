# Vulnerability: Speedrun User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`speedrun.yaml`)

## Description
Speedrun user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.speedrun.com/user/{{user}}/
```

