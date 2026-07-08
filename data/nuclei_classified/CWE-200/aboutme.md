# Vulnerability: About.me User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`aboutme.yaml`)

## Description
About.me user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://about.me/{{user}}
```

