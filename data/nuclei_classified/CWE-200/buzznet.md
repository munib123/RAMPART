# Vulnerability: Buzznet User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`buzznet.yaml`)

## Description
Buzznet user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.buzznet.com/author/{{user}}/
```

