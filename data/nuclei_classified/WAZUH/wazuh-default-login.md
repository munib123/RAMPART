# Vulnerability: Wazuh - Default Login
**Classification:** WAZUH
**Source:** Nuclei Template (`wazuh-default-login.yaml`)

## Description
Wazuh contains default credentials. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/app/login
POST /auth/login HTTP/1.1
Host: {{Hostname}}
Osd-Version: {{osd}}
osd-xsrf: osd-fetch
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

