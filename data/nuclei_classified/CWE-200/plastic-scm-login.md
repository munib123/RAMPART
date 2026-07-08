# Vulnerability: Unity Plastic SCM Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`plastic-scm-login.yaml`)

## Description
Unity Plastic SCM login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/account
```

