# Nuclei Template: Riello UPS NetMan 204 Network Card - Default Login
**Template ID:** netman-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`netman-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Default logins on Riello UPS NetMan 204 is used. Attacker can access to UPS and attacker can manipulate the UPS settings to disrupt the onsite systems.

## Steps to reproduce / Exploit Payload
```http
GET /cgi-bin/login.cgi?username={{username}}&password={{password}} HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.riello-ups.com/
