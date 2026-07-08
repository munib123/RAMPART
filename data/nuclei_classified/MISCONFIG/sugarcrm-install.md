# Vulnerability: SugarCRM Exposed Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`sugarcrm-install.yaml`)

## Description
SugarCRM is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

