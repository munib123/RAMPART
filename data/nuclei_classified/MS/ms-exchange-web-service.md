# Vulnerability: Microsoft Exchange Web Service - Detect
**Classification:** MS
**Source:** Nuclei Template (`ms-exchange-web-service.yaml`)

## Description
Microsoft Exchange Web Services was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/EWS/Exchange.asmx
GET {{BaseURL}}/owa/service.svc
```

