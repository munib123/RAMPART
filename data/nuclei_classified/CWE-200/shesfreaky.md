# Vulnerability: Shesfreaky User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`shesfreaky.yaml`)

## Description
Shesfreaky user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.shesfreaky.com/profile/{{user}}/
```

