# Vulnerability: Minio Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`minio-default-login.yaml`)

## Description
Minio default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /minio/webrpc HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"id":1,"jsonrpc":"2.0","params":{"username":"{{username}}","password":"{{password}}"},"method":"Web.Login"}

POST /minio/webrpc HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"id":1,"jsonrpc":"2.0","params":{"username":"{{username}}","password":"{{password}}"},"method":"web.Login"}
```

