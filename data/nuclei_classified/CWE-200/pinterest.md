# Vulnerability: Pinterest User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pinterest.yaml`)

## Description
Pinterest user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.pinterest.com/{{user}}/
```

