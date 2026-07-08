# Vulnerability: Oracle WebLogic UDDI Explorer Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`weblogic-uddiexplorer.yaml`)

## Description
Oracle WebLogic UDDI Explorer panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/uddiexplorer/
```

