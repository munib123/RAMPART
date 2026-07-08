# Vulnerability: Chaturbate User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`chaturbate.yaml`)

## Description
Chaturbate user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://chaturbate.com/{{user}}/
```

