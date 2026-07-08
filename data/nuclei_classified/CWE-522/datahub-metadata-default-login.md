# Vulnerability: DataHub Metadata - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`datahub-metadata-default-login.yaml`)

## Description
DataHub Metadata contains a default login vulnerability.  An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /logIn HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

