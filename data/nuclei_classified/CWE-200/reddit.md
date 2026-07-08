# Vulnerability: Reddit User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`reddit.yaml`)

## Description
Reddit user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.reddit.com/user/{{user}}/about/.json
```

