# Vulnerability: YouTube User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`youtube.yaml`)

## Description
YouTube user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.youtube.com/c/{{user}}/about
GET https://www.youtube.com/user/{{user}}/about
GET https://www.youtube.com/@{{user}}
```

