# Vulnerability: GoCD Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gocd-login.yaml`)

## Description
GoCD login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/go/auth/login
```

