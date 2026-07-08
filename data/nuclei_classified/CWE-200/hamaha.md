# Vulnerability: Hamaha User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hamaha.yaml`)

## Description
Hamaha user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hamaha.net/{{user}}
```

