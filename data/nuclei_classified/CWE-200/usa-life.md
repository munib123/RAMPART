# Vulnerability: USA Life User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`usa-life.yaml`)

## Description
USA Life user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://usa.life/{{user}}
```

