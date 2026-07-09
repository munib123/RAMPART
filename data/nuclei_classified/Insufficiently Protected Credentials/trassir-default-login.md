# Nuclei Template: Trassir WebView Default Login - Detect
**Template ID:** trassir-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`trassir-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Trassir WebView contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}

username={{username}}&password={{password}}
```

## References
- https://confluence.trassir.com/display/TKB/How+to+reset+the+administrator+password+on+the+TRASSIR+NVR
