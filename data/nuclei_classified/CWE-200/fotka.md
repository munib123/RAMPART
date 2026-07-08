# Vulnerability: Fotka User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fotka.yaml`)

## Description
Fotka user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.fotka.com/v2/user/dataStatic?login={{user}}
```

