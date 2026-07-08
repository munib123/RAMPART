# Vulnerability: Dissenter User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dissenter.yaml`)

## Description
Dissenter user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://dissenter.com/user/{{user}}
```

