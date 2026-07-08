# Vulnerability: Voice123 User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`voice123.yaml`)

## Description
Voice123 user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://voice123.com/api/providers/search/{{user}}
```

