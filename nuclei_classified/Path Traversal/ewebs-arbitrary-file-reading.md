# Nuclei Template: EWEBS - Local File Inclusion
**Template ID:** ewebs-arbitrary-file-reading
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`ewebs-arbitrary-file-reading.yaml`)

## Vulnerability Information & PoC

## Description
EWEBS is vulnerable to local file inclusion and allows remote attackers to disclose the content of locally stored files via the 'Language_S' parameter supplied to the 'casmain.xgi' endpoint.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/casmain.xgi
```

## References
- http://wiki.peiqi.tech/PeiQi_Wiki/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E6%9E%81%E9%80%9AEWEBS/%E6%9E%81%E9%80%9AEWEBS%20casmain.xgi%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.html
