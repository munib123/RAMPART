# Vulnerability: VMware Detection
**Classification:** TECH
**Source:** Nuclei Template (`vmware-detect.yaml`)

## Description
Sends a POST request containing a SOAP payload to a vCenter server to obtain version information

## Vulnerable Code Pattern / Exploit Payload
```http
POST /sdk/ HTTP/1.1
Host: {{Hostname}}

<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <soap:Header>
      <operationID>00000001-00000001</operationID>
   </soap:Header>
   <soap:Body>
      <RetrieveServiceContent xmlns="urn:internalvim25">
         <_this xsi:type="ManagedObjectReference" type="ServiceInstance">ServiceInstance</_this>
      </RetrieveServiceContent>
   </soap:Body>
</soap:Envelope>
```

