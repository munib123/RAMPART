# Vulnerability: Symantec Phishing Readiness Platform Console
**Classification:** SYMANTEC
**Source:** Nuclei Template (`symantec-phishing-panel.yaml`)

## Description
Management Console for Symantec Phishing Readiness Platform

## Vulnerable Code Pattern / Exploit Payload
```http
GET /users/sign_in HTTP/1.1
Host: {{company}}.securitytraining.io
```

