# Vulnerability: JHipster Platform - Default Login
**Classification:** JHIPSTER
**Source:** Nuclei Template (`jhipster-default-login.yaml`)

## Description
Detects the presence of JHipster application dashboard or API endpoints that allow authentication using default credentials. JHipster applications by default are often configured with the username "admin" and password "admin", potentially exposing application management interfaces or sensitive APIs if not changed after deployment.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/authenticate HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}","rememberMe":false}
```

