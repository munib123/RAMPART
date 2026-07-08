# Vulnerability: Caprover - Default Login
**Classification:** CAPROVER
**Source:** Nuclei Template (`caprover-default-login.yaml`)

## Description
Caprover defaultl login has been detected.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v2/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
x-namespace: captain

{"password":"{{password}}"}
```

