# Vulnerability: JumpServer Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jumpserver-panel.yaml`)

## Description
JumpServer Open Source Bastion Host login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/core/auth/login/
GET {{BaseURL}}/users/login/
```

