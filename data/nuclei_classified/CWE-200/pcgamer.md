# Vulnerability: PCGamer User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pcgamer.yaml`)

## Description
PCGamer user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://forums.pcgamer.com/members/{{user}}/
```

