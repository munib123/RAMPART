# Vulnerability: Codeforces User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`codeforces.yaml`)

## Description
Codeforces user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://codeforces.com/profile/{{user}}
```

