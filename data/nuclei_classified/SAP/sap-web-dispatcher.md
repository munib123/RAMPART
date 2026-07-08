# Vulnerability: SAP Web Dispatcher detection
**Classification:** SAP
**Source:** Nuclei Template (`sap-web-dispatcher.yaml`)

## Description
Detection of SAP Web Dispatcher service

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/inormalydonotexist
```

