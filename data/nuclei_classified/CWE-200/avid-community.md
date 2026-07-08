# Vulnerability: Avid Community User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`avid-community.yaml`)

## Description
Avid Community user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://community.avid.com/members/{{user}}/default.aspx
```

