# Vulnerability: Sessionize User Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sessionize.yaml`)

## Description
Sessionize user profile information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://sessionize.com/{{user}}
```

