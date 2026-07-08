# Vulnerability: Microsoft Azure Domain Tenant ID - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`azure-domain-tenant.yaml`)

## Description
Microsoft Azure Domain Tenant ID was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
@Host: https://login.microsoftonline.com:443
GET /{{Host}}/v2.0/.well-known/openid-configuration HTTP/1.1
Host: login.microsoftonline.com
```

