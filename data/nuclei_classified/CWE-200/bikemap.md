# Vulnerability: Bikemap User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bikemap.yaml`)

## Description
Bikemap user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.bikemap.net/en/u/{{user}}/routes/created/
```

