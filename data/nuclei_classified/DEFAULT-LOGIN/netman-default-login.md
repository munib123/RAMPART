# Vulnerability: Riello UPS NetMan 204 Network Card - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`netman-default-login.yaml`)

## Description
Default logins on Riello UPS NetMan 204 is used. Attacker can access to UPS and attacker can manipulate the UPS settings to disrupt the onsite systems.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /cgi-bin/login.cgi?username={{username}}&password={{password}} HTTP/1.1
Host: {{Hostname}}
```

