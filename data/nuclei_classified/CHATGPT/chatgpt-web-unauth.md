# Vulnerability: ChatGPT Web - Unauthorized Access
**Classification:** CHATGPT
**Source:** Nuclei Template (`chatgpt-web-unauth.yaml`)

## Description
ChatGPT Web is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/session HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{}
```

