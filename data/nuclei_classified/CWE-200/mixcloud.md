# Vulnerability: Mixcloud User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mixcloud.yaml`)

## Description
Mixcloud user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.mixcloud.com/{{user}}/
```

