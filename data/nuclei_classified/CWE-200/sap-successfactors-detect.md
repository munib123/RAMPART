# Vulnerability: SAP SuccessFactors Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sap-successfactors-detect.yaml`)

## Description
SAP SuccessFactors login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/sf/start
```

