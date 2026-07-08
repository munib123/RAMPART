# Vulnerability: SAP NetWeaver ICM Info page leak
**Classification:** SAP
**Source:** Nuclei Template (`sap-netweaver-info-leak.yaml`)

## Description
Detection of SAP NetWeaver ABAP Webserver /public/info page

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sap/public/info
```

