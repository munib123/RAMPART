# Vulnerability: Genius Users User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`genius-users.yaml`)

## Description
Genius Users user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://genius.com/{{user}}
```

