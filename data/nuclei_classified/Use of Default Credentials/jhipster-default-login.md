# Nuclei Template: JHipster Platform - Default Login
**Template ID:** jhipster-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`jhipster-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detects the presence of JHipster application dashboard or API endpoints that allow authentication using default credentials. JHipster applications by default are often configured with the username "admin" and password "admin", potentially exposing application management interfaces or sensitive APIs if not changed after deployment.

## Steps to reproduce / Exploit Payload
```http
POST /api/authenticate HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}","rememberMe":false}
```

## References
- https://www.jhipster.tech/security/
