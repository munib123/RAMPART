# Vulnerability: Salesforce Credentials - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`salesforce-credentials.yaml`)

## Description
Salesforce credentials information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/js/salesforce.js
GET {{BaseURL}}/salesforce.js
```

