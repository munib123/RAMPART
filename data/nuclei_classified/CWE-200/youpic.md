# Vulnerability: Youpic User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`youpic.yaml`)

## Description
Youpic user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://youpic.com/photographer/{{user}}
```

