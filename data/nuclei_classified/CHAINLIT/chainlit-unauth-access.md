# Vulnerability: Chainlit - Unauthenticated Access
**Classification:** CHAINLIT
**Source:** Nuclei Template (`chainlit-unauth-access.yaml`)

## Description
Detects Chainlit AI chatbot instances with no authentication, leaving the entire app publicly accessible by default.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}
Accept: application/json

GET /project/settings HTTP/1.1
Host: {{Hostname}}
Accept: application/json
```

