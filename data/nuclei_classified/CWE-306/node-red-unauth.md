# Vulnerability: Node-RED - Unauthenticated Access
**Classification:** CWE-306
**Source:** Nuclei Template (`node-red-unauth.yaml`)

## Description
Node-RED flow editor is accessible without authentication. Node-RED is a flow-based programming tool that can execute arbitrary system commands, read/write files, and make network requests. Unauthenticated access leads to remote code execution.

## Secure Mitigation
Enable authentication in Node-RED settings.js by configuring adminAuth with username and bcrypt-hashed password. Restrict network access to trusted IPs only.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/flows
```

