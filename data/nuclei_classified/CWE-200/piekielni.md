# Vulnerability: Piekielni User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`piekielni.yaml`)

## Description
Piekielni user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://piekielni.pl/user/{{user}}
```

