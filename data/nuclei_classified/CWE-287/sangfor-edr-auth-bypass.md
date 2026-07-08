# Vulnerability: Sangfor EDR - Authentication Bypass
**Classification:** CWE-287
**Source:** Nuclei Template (`sangfor-edr-auth-bypass.yaml`)

## Description
Sangfor EDR contains an authentication bypass vulnerability. An attacker can access the system with admin privileges by accessing the login page directly using a provided username rather than going through the login screen without providing a username. This makes it possible to obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/login.php?user=admin
```

