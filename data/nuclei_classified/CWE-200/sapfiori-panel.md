# Vulnerability: SAP Fiori Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sapfiori-panel.yaml`)

## Description
SAP Fiori login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/fiori
GET {{BaseURL}}/irj/portal/fiori
```

