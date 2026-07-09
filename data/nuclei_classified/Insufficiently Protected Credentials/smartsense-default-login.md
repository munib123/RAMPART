# Nuclei Template: HortonWorks SmartSense Default Login
**Template ID:** smartsense-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`smartsense-default-login.yaml`)

## Vulnerability Information & PoC

## Description
HortonWorks SmartSense default admin login information was detected.

## Steps to reproduce / Exploit Payload
```http
GET /apt/v1/context HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

## References
- https://docs.cloudera.com/HDPDocuments/SS1/SmartSense-1.2.2/bk_smartsense_admin/content/manual_server_login.html
