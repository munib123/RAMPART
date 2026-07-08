# Vulnerability: Hackerearth User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hackerearth.yaml`)

## Description
Hackerearth user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.hackerearth.com/@{{user}}
```

