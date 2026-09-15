# Nuclei Template: Node.js Express NODE_ENV Development Mode
**Template ID:** node-express-dev-env
**Vulnerability Class:** Information Exposure Through an Error Message
**Severity:** Medium
**CWE:** CWE-209
**Source:** Nuclei Template (`node-express-dev-env.yaml`)

## Vulnerability Information & PoC

## Description
The Node.js application runs in development mode, which can expose sensitive information, such as source code and secrets, depending on the application.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Connection: close

t
```

## References
- https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/express-development-mode-is-enabled/
- https://www.synopsys.com/blogs/software-security/nodejs-mean-stack-vulnerabilities.html
