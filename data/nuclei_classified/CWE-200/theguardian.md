# Vulnerability: Theguardian User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`theguardian.yaml`)

## Description
Theguardian user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.theguardian.com/profile/{{user}}
```

