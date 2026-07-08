# Vulnerability: SAP NetWeaver Portal - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sap-netweaver-portal.yaml`)

## Description
SAP NetWeaver Portal login has been detected. Note that NetWeaver has multiple default passwords as listed in the references.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/irj/portal
```

