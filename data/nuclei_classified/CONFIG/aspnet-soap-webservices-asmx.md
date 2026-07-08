# Vulnerability: SOAP-based ASP.NET web services ASMX - Detect
**Classification:** CONFIG
**Source:** Nuclei Template (`aspnet-soap-webservices-asmx.yaml`)

## Description
SOAP-based ASP.NET web services collection was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

