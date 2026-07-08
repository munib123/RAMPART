# Vulnerability: NocoDB Public Registration Enabled
**Classification:** NOCODB
**Source:** Nuclei Template (`nocodb-public-registration-enabled.yaml`)

## Description
Detected NocoDB instances that allow public user registration without requiring an invitation. This misconfiguration allows anyone to create an account on the NocoDB instance, potentially leading to unauthorized access to databases and sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v1/auth/user/signup HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"email":"{{email}}","password":"{{password}}"}
```

