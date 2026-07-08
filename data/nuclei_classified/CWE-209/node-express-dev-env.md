# Vulnerability: Node.js Express NODE_ENV Development Mode
**Classification:** CWE-209
**Source:** Nuclei Template (`node-express-dev-env.yaml`)

## Description
The Node.js application runs in development mode, which can expose sensitive information, such as source code and secrets, depending on the application.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Connection: close

t
```

