# Vulnerability: Teespring User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`teespring.yaml`)

## Description
Teespring user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://commerce.teespring.com/v1/stores?slug={{user}}
```

