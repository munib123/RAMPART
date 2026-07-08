# Vulnerability: Unauthenticated LDAP Account Manager
**Classification:** LDAP
**Source:** Nuclei Template (`unauth-ldap-account-manager.yaml`)

## Description
LDAP Account Manager is exposed to external users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/templates/config/profmanage.php
```

