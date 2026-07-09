# Nuclei Template: Salesforce Credentials - Detect
**Template ID:** salesforce-credentials
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`salesforce-credentials.yaml`)

## Vulnerability Information & PoC

## Description
Salesforce credentials information was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/js/salesforce.js
GET {{BaseURL}}/salesforce.js
```

## References
- https://github.com/daveagp/websheets
