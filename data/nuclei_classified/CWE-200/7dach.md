# Vulnerability: 7dach User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`7dach.yaml`)

## Description
7dach user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://7dach.ru/profile/{{user}}
```

