# Vulnerability: Soup User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`soup.yaml`)

## Description
Soup user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.soup.io/author/{{user}}
```

