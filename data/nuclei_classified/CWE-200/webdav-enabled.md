# Vulnerability: WebDAV Protocol - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`webdav-enabled.yaml`)

## Description
WebDAV protocol was detected.

## Secure Mitigation
Recommended disabling if not currently in use.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

OPTIONS / HTTP/1.1
Host: {{Hostname}}

OPTIONS / HTTP/1.1
Host: {{Hostname}}
Authorization: Basic YW5vbnltb3VzOmFub255bW91cw==
```

