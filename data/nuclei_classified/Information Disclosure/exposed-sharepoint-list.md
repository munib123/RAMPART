# Nuclei Template: Sharepoint List - Detect
**Template ID:** exposed-sharepoint-list
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`exposed-sharepoint-list.yaml`)

## Vulnerability Information & PoC

## Description
Sharepoint list was detected because of improper configuration. An anonymous user can access SharePoint Web Services.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/_vti_bin/lists.asmx?WSDL
```

## References
- https://hackerone.com/reports/761158
- https://hackerone.com/reports/300539
