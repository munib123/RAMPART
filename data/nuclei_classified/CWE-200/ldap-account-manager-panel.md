# Vulnerability: LDAP Account Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ldap-account-manager-panel.yaml`)

## Description
LDAP Account Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/templates/login.php
GET {{BaseURL}}/lam/templates/login.php
```

