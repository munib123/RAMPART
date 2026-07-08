# Vulnerability: Fark User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fark.yaml`)

## Description
Fark user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.fark.com/users/{{user}}
```

