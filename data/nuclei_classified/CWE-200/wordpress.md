# Vulnerability: WordPress User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wordpress.yaml`)

## Description
WordPress user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://profiles.wordpress.org/{{user}}/
```

