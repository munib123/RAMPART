# Vulnerability: Minds User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`minds.yaml`)

## Description
Minds user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.minds.com/{{user}}/
```

