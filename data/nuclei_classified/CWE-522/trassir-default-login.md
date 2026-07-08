# Vulnerability: Trassir WebView Default Login - Detect
**Classification:** CWE-522
**Source:** Nuclei Template (`trassir-default-login.yaml`)

## Description
Trassir WebView contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}

username={{username}}&password={{password}}
```

