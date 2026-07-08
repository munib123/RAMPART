# Vulnerability: Vtiger CRM Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`vtiger-installer.yaml`)

## Description
Vtiger CRM is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?module=Install&view=Index
```

