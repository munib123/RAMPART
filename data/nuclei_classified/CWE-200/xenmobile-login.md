# Vulnerability: Xenmobile Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xenmobile-login.yaml`)

## Description
Xenmobile Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/zdm/login_xdm_uc.jsp
```

