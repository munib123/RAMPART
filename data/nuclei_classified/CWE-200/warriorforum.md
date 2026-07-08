# Vulnerability: Warriorforum User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`warriorforum.yaml`)

## Description
Warriorforum user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.warriorforum.com/members/{{user}}.html
```

