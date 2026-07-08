# Vulnerability: Jira Service Desk Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`servicedesk-login-panel.yaml`)

## Description
Jira Service Desk login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/servicedesk/customer/user/login
GET {{BaseURL}}/servicedesk/customer/portal/10/user/login
```

