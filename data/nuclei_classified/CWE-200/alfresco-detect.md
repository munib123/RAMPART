# Vulnerability: Alfresco CMS Detection
**Classification:** CWE-200
**Source:** Nuclei Template (`alfresco-detect.yaml`)

## Description
Alfresco CMS was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/alfresco/api/-default-/public/cmis/versions/1.1/atom
```

