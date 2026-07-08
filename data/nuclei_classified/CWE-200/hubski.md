# Vulnerability: Hubski User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hubski.yaml`)

## Description
Hubski user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hubski.com/user/{{user}}
```

