# Vulnerability: Sharepoint List - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`exposed-sharepoint-list.yaml`)

## Description
Sharepoint list was detected because of improper configuration. An anonymous user can access SharePoint Web Services.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_vti_bin/lists.asmx?WSDL
```

