# Nuclei Template: Node-RED - Unauthenticated Access
**Template ID:** node-red-unauth
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** High
**CWE:** CWE-306
**Source:** Nuclei Template (`node-red-unauth.yaml`)

## Vulnerability Information & PoC

## Description
Node-RED flow editor is accessible without authentication. Node-RED is a flow-based programming tool that can execute arbitrary system commands, read/write files, and make network requests. Unauthenticated access leads to remote code execution.

## Impact
An attacker can create flows that execute system commands on the server, read sensitive files, establish reverse shells, or pivot to internal networks. Node-RED's exec node provides direct OS command execution.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/flows
```

## Remediation
Enable authentication in Node-RED settings.js by configuring adminAuth with username and bcrypt-hashed password. Restrict network access to trusted IPs only.

## References
- https://nodered.org/docs/user-guide/runtime/securing-node-red
- https://nodered.org/docs/user-guide/runtime/configuration
