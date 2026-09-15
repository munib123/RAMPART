# Nuclei Template: Unauthenticated LDAP Account Manager
**Template ID:** unauth-ldap-account-manager
**Vulnerability Class:** LDAP Injection
**Severity:** Medium
**Source:** Nuclei Template (`unauth-ldap-account-manager.yaml`)

## Vulnerability Information & PoC

## Description
LDAP Account Manager is exposed to external users.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/templates/config/profmanage.php
```

