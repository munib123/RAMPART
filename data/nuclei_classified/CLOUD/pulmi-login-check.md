# Vulnerability: pulmi.com Login Check
**Classification:** CLOUD
**Source:** Nuclei Template (`pulmi-login-check.yaml`)

## Description
Checks for a valid github account.

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://api.pulumi.com/api/console/email/login HTTP/1.1
Host: api.pulumi.com
Content-Type: application/json
Origin: https://app.pulumi.com
Referer: https://app.pulumi.com/

{"emailOrLogin":"{{username}}","password":"{{password}}"}
```

