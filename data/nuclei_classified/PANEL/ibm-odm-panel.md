# Vulnerability: IBM Operational Decision Manager Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`ibm-odm-panel.yaml`)

## Description
IBM Operational Decision Manager panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/decisioncenter/login
```

