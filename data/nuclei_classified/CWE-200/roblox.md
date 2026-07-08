# Vulnerability: Roblox User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`roblox.yaml`)

## Description
Roblox user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://auth.roblox.com/v1/usernames/validate?username={{user}}&birthday=2019-12-31T23:00:00.000Z
```

