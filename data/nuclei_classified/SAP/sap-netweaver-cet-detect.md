# Vulnerability: SAP NetWeaver Composition Environment Tools - Detect
**Classification:** SAP
**Source:** Nuclei Template (`sap-netweaver-cet-detect.yaml`)

## Description
Detects the presence of the SAP NetWeaver Process Integration / Composition Environment Tools page

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/rep/start/index.jsp
```

