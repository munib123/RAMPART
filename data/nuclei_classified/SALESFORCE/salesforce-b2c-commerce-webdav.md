# Vulnerability: Salesforce B2C Commerce WebDAV - Detection
**Classification:** SALESFORCE
**Source:** Nuclei Template (`salesforce-b2c-commerce-webdav.yaml`)

## Description
Detects Salesforce B2C Commerce WebDAV by checking for specific patterns in a 404 response.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

